"""
Deferred Graph Modifier for Microcode CFG Changes

This module provides a queue-based system for deferring CFG modifications
until all analysis is complete. This prevents issues that occur when
modifying the graph during iteration.

Based on the pattern described by hex-rays plugin developers:
- Queue all graph modifications during analysis
- Apply them in a controlled order after analysis completes
- Handle instruction removals last to preserve tracking information

Supported modification types:
- block_target_change: Change a conditional jump's target
- block_fallthrough_change: Change a block's fallthrough successor
- block_goto_change: Change an unconditional goto's destination
- block_nop_insns: NOP specific instructions in a block
- block_convert_to_goto: Convert a 2-way block to a 1-way goto
- insn_remove: Remove a specific instruction (deferred until end)

Choosing Between Deferred and Immediate Modifiers
=================================================

Use **DeferredGraphModifier** when:
- Your optimizer iterates over multiple blocks before making changes
- Other rules may be analyzing the same CFG concurrently
- You need atomic "all-or-nothing" modification semantics
- The optimizer is part of a multi-rule pass (e.g., unflattening)

Use **ImmediateGraphModifier** when:
- Changes are isolated and don't affect other blocks being analyzed
- You need changes to be visible immediately for subsequent analysis
- The optimizer runs in isolation (single-rule pass)
- Performance is critical and queuing overhead is undesirable

Example: Deferred Optimizer (Recommended Pattern)
=================================================

This pattern separates analysis from modification, preventing stale pointers::

    from dataclasses import dataclass
    from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier

    @dataclass
    class PendingChange:
        '''Store only serials/EAs - NEVER live pointers.'''
        block_serial: int
        target_serial: int
        description: str = ""

    class MyDeferredOptimizer(GenericUnflatteningRule):
        '''Optimizer using deferred CFG modification pattern.'''

        def __init__(self):
            super().__init__()
            self._pending_changes: list[PendingChange] = []
            self._modifier: DeferredGraphModifier | None = None

        def optimize(self, blk: mblock_t) -> int:
            '''Main entry point - orchestrates analyze-then-apply.'''
            # Initialize modifier for this optimization pass
            self._modifier = DeferredGraphModifier(self.mba)
            self._pending_changes.clear()

            # Phase 1: Analysis - queue all modifications
            # IMPORTANT: Do NOT modify CFG here, only collect what needs changing
            nb_queued = self.analyze_blk(blk)

            if nb_queued == 0:
                return 0

            # Phase 2: Apply - execute all modifications atomically
            return self._apply_queued_modifications()

        def analyze_blk(self, blk: mblock_t) -> int:
            '''Analyze block and queue modifications. Returns count queued.'''
            # Store only serials, not pointers!
            if self._should_redirect(blk):
                self._pending_changes.append(PendingChange(
                    block_serial=blk.serial,        # int, not mblock_t*
                    target_serial=blk.succ(0),      # int, not mblock_t*
                    description=f"redirect block {blk.serial}"
                ))
                return 1
            return 0

        def _apply_queued_modifications(self) -> int:
            '''Apply all queued modifications with fresh pointers.'''
            applied = 0
            for change in self._pending_changes:
                # Re-fetch block using serial (fresh pointer)
                blk = self.mba.get_mblock(change.block_serial)
                if blk is None:
                    continue  # Block may have been removed

                # Now safe to use the modifier
                self._modifier.queue_goto_change(
                    block_serial=change.block_serial,
                    new_target=change.target_serial,
                    description=change.description
                )
                applied += 1

            # Apply all queued changes
            if self._modifier.has_modifications():
                return self._modifier.apply()
            return 0

Example: Immediate Optimizer (Simple Cases)
===========================================

Use this pattern only when modifications are isolated::

    from d810.hexrays.mutation.deferred_modifier import ImmediateGraphModifier

    class MyImmediateOptimizer(GenericUnflatteningRule):
        '''Optimizer using immediate CFG modification pattern.

        WARNING: Only use when changes don't affect other blocks being
        analyzed in the same pass. For multi-block analysis, use
        DeferredGraphModifier instead.
        '''

        def __init__(self):
            super().__init__()
            self._modifier: ImmediateGraphModifier | None = None

        def optimize(self, blk: mblock_t) -> int:
            '''Analyze and modify single block immediately.'''
            self._modifier = ImmediateGraphModifier(self.mba)

            # Analysis and modification happen together
            if self._should_redirect(blk):
                # Change is applied immediately
                self._modifier.queue_goto_change(
                    block_serial=blk.serial,
                    new_target=self._compute_target(blk),
                    description=f"redirect block {blk.serial}"
                )

            # Finalize (runs optimize_local, verify)
            return self._modifier.apply()

Best Practices
==============

1. **Never store live pointers across CFG modifications**::

       # BAD - pointer may become stale
       self.saved_block = blk
       self.modify_cfg()
       self.saved_block.tail  # CRASH: stale pointer

       # GOOD - store serial, re-fetch when needed
       self.saved_serial = blk.serial
       self.modify_cfg()
       fresh_blk = self.mba.get_mblock(self.saved_serial)

2. **Use dup_mop() for operand copies**::

       from d810.hexrays.utils.hexrays_helpers import dup_mop

       # BAD - shallow copy, shares underlying data
       saved_op = mop_t(blk.tail.l)

       # GOOD - deep copy, safe to use after CFG changes
       saved_op = dup_mop(blk.tail.l)

3. **Clear pending changes after apply**::

       def _apply_queued_modifications(self) -> int:
           result = self._modifier.apply()
           self._pending_changes.clear()  # Prevent accidental reuse
           return result

4. **Check block existence before use**::

       blk = self.mba.get_mblock(saved_serial)
       if blk is None:
           logger.warning("Block %d no longer exists", saved_serial)
           return 0

See Also
========
- ABCBlockSplitter: Reference implementation of deferred pattern
- FixPredecessorOfConditionalJumpBlock: Another deferred pattern example
- GenericDispatcherUnflatteningRule: Orchestrates multiple deferred rules
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
import uuid

from d810.core.typing import TYPE_CHECKING, Callable
import os

import ida_hexrays

from d810.core import getLogger
from d810.hexrays.mutation.deferred_events import DeferredEvent, EventEmitter
from d810.hexrays.mutation.cfg_verify import (
    capture_failure_artifact)
from d810.hexrays.mutation.cfg_mutations import (
    change_0way_block_successor)
from d810.hexrays.mutation.cfg_mutations import (
    change_1way_block_successor)
from d810.hexrays.mutation.cfg_mutations import (
    change_2way_block_conditional_successor)
from d810.hexrays.mutation.cfg_mutations import (
    create_block)
from d810.hexrays.mutation.cfg_mutations import (
    create_standalone_block)
from d810.hexrays.mutation.cfg_mutations import (
    duplicate_block)
from d810.hexrays.mutation.cfg_mutations import (
    insert_nop_blk)
from d810.hexrays.mutation.cfg_mutations import (
    insert_goto_instruction)
from d810.hexrays.mutation.cfg_verify import (
    log_block_info)
from d810.hexrays.mutation.cfg_mutations import (
    make_2way_block_goto)
from d810.hexrays.mutation.cfg_mutations import (
    mba_deep_cleaning)
from d810.hexrays.mutation.cfg_verify import (
    safe_verify)
from d810.hexrays.mutation.cfg_verify import (
    snapshot_block_for_capture)
from d810.hexrays.mutation.cfg_mutations import (
    remove_block_edge)
from d810.hexrays.mutation.cfg_mutations import (
    _rewire_edge)
from d810.cfg.flowgraph import FlowGraph, InsnSnapshot
from d810.hexrays.mutation.insn_snapshot_materializer import (
    materialize_insn_snapshots,
)
from d810.hexrays.mutation.ir_translator import lift

if TYPE_CHECKING:
    pass

logger = getLogger("D810.deferred_modifier")

_MAX_CAPTURE_HISTORY = 12


def _env_flag(name: str) -> bool:
    value = os.environ.get(name, "").strip().lower()
    return value in ("1", "true", "yes", "on")


def _parse_watch_edges_env() -> set[tuple[int, int]]:
    """Parse debug watch edge env vars into {(src, dst), ...} set.

    Supported vars:
      - D810_DEFERRED_WATCH_EDGE="381:382"
      - D810_DEFERRED_WATCH_EDGES="381:382,0x17d:0x17e"
    """
    raw = ",".join(
        part for part in (
            os.environ.get("D810_DEFERRED_WATCH_EDGE", ""),
            os.environ.get("D810_DEFERRED_WATCH_EDGES", ""),
        ) if part
    ).strip()
    if not raw:
        return set()
    edges: set[tuple[int, int]] = set()
    for token in raw.split(","):
        token = token.strip()
        if not token or ":" not in token:
            continue
        lhs, rhs = token.split(":", 1)
        try:
            edges.add((int(lhs, 0), int(rhs, 0)))
        except ValueError:
            continue
    return edges


def _format_block_info(blk: ida_hexrays.mblock_t) -> str:
    """Format detailed block information for debugging."""
    if blk is None:
        return "<None>"

    # Block type names
    blk_type_names = {
        ida_hexrays.BLT_NONE: "NONE",
        ida_hexrays.BLT_STOP: "STOP",
        ida_hexrays.BLT_0WAY: "0WAY",
        ida_hexrays.BLT_1WAY: "1WAY",
        ida_hexrays.BLT_2WAY: "2WAY",
        ida_hexrays.BLT_NWAY: "NWAY",
        ida_hexrays.BLT_XTRN: "XTRN",
    }
    blk_type = blk_type_names.get(blk.type, f"UNK({blk.type})")

    # Successors
    succs = []
    for i in range(blk.nsucc()):
        succs.append(blk.succ(i))
    succ_str = f"succs={succs}" if succs else "succs=[]"

    # Predecessors
    preds = []
    for i in range(blk.npred()):
        preds.append(blk.pred(i))
    pred_str = f"preds={preds}" if preds else "preds=[]"

    # Tail instruction
    tail_str = "tail=None"
    if blk.tail:
        opcode_name = ida_hexrays.get_mreg_name(blk.tail.opcode, 1) or str(blk.tail.opcode)
        tail_str = f"tail.opcode={blk.tail.opcode} tail.ea={hex(blk.tail.ea)}"

    return f"blk[{blk.serial}] type={blk_type} {succ_str} {pred_str} {tail_str}"


def _format_insn_info(insn: ida_hexrays.minsn_t) -> str:
    """Format instruction information for debugging."""
    if insn is None:
        return "<None>"
    return f"insn[ea={hex(insn.ea)} opcode={insn.opcode}]"


def _collect_capture_blocks(*snapshots: dict | None) -> list[int]:
    block_serials: set[int] = set()
    for snap in snapshots:
        if not snap:
            continue
        serial = snap.get("serial")
        if isinstance(serial, int):
            block_serials.add(serial)
        for key in ("succs", "preds"):
            for item in snap.get(key, []) or []:
                if isinstance(item, int):
                    block_serials.add(item)
    return sorted(block_serials)


class ModificationType(Enum):
    """Types of graph modifications that can be queued."""
    BLOCK_GOTO_CHANGE = auto()       # Change goto destination
    BLOCK_TARGET_CHANGE = auto()      # Change conditional jump target
    BLOCK_FALLTHROUGH_CHANGE = auto() # Change fallthrough successor
    BLOCK_CONVERT_TO_GOTO = auto()    # Convert 2-way to 1-way block
    BLOCK_NOP_INSNS = auto()          # NOP instructions in a block
    INSN_REMOVE = auto()              # Remove a specific instruction
    INSN_NOP = auto()                 # NOP a specific instruction
    BLOCK_CREATE_WITH_REDIRECT = auto()  # Create intermediate block and redirect
    BLOCK_CREATE_WITH_CONDITIONAL_REDIRECT = auto()  # Create conditional 2-way block with redirect
    BLOCK_DUPLICATE_AND_REDIRECT = auto()  # Duplicate source block and redirect one predecessor
    EDGE_REDIRECT_VIA_PRED_SPLIT = auto()  # Clone src block; redirect one predecessor to clone
    EDGE_SPLIT_TRAMPOLINE = auto()  # Materialize standalone trampoline and redirect one predecessor
    EDGE_REMOVE = auto()  # Remove a single edge (2-way→1-way or 1-way→0-way)
    PRIVATE_TERMINAL_SUFFIX = auto()  # Clone shared suffix chain per anchor
    PRIVATE_TERMINAL_SUFFIX_GROUP = auto()  # Clone shared suffix chain for multiple anchors atomically
    DIRECT_TERMINAL_LOWERING_GROUP = auto()  # Direct terminal lowering for multiple anchors


class TargetRefKind(Enum):
    """How a modification target should be interpreted at apply-time."""
    ABSOLUTE = auto()
    STOP_BLOCK = auto()  # Resolve to current mba.qty - 1 at apply-time


@dataclass
class GraphModification:
    """Represents a single queued graph modification."""
    mod_type: ModificationType
    block_serial: int
    # Target for goto/jump changes
    new_target: int | None = None
    # For instruction-level operations
    insn_ea: int | None = None
    # Priority for ordering (lower = earlier)
    priority: int = 100
    # Description for logging
    description: str = ""
    # For BLOCK_CREATE_WITH_REDIRECT: instructions to copy to new block
    instructions_to_copy: list | None = None
    # For BLOCK_CREATE_WITH_REDIRECT: final target after intermediate block
    final_target: int | None = None
    # For BLOCK_CREATE_WITH_REDIRECT: whether target is 0-way
    is_0_way: bool = False
    # Rule priority for conflict resolution (higher = wins conflicts)
    rule_priority: int = 0
    # For BLOCK_CREATE_WITH_CONDITIONAL_REDIRECT: conditional jump target
    conditional_target: int | None = None
    # For BLOCK_CREATE_WITH_CONDITIONAL_REDIRECT: fallthrough target
    fallthrough_target: int | None = None
    # For BLOCK_CREATE_WITH_CONDITIONAL_REDIRECT: expected final serials
    expected_conditional_serial: int | None = None
    expected_fallthrough_serial: int | None = None
    # For EDGE_REDIRECT_VIA_PRED_SPLIT: block to clone
    src_block: int | None = None
    # For EDGE_REDIRECT_VIA_PRED_SPLIT: current successor being replaced on clone
    old_target: int | None = None
    # For EDGE_REDIRECT_VIA_PRED_SPLIT: predecessor whose edge gets redirected to clone
    via_pred: int | None = None
    # For EDGE_REDIRECT_VIA_PRED_SPLIT: future corridor cloning endpoint (unused, stub)
    clone_until: int | None = None
    # For EDGE_SPLIT_TRAMPOLINE: expected final serial assigned by PatchPlan compilation
    expected_serial: int | None = None
    # For block-creation operations that materialize multiple blocks
    expected_secondary_serial: int | None = None
    # How to resolve new_target at apply-time
    target_ref_kind: TargetRefKind = TargetRefKind.ABSOLUTE
    # For PRIVATE_TERMINAL_SUFFIX: ordered suffix serials to clone
    suffix_serials: tuple[int, ...] | None = None
    # For PRIVATE_TERMINAL_SUFFIX: expected serials for each cloned block
    clone_expected_serials: tuple[int, ...] | None = None
    # For PRIVATE_TERMINAL_SUFFIX_GROUP: all anchor serials
    anchors: tuple[int, ...] | None = None
    # For PRIVATE_TERMINAL_SUFFIX_GROUP: per-anchor expected clone serials (parallel to anchors)
    per_anchor_clone_expected_serials: tuple[tuple[int, ...], ...] | None = None
    # For DIRECT_TERMINAL_LOWERING_GROUP: per-site lowering specifications
    sites: tuple | None = None


def _prepare_block_creation_instructions(
    mba: "ida_hexrays.mba_t",
    instructions_to_copy: list | tuple | None,
) -> list:
    if instructions_to_copy is None:
        return []

    instructions = list(instructions_to_copy)
    if not instructions:
        return []

    has_symbolic = any(isinstance(insn, InsnSnapshot) for insn in instructions)
    if not has_symbolic:
        return instructions
    if not all(isinstance(insn, InsnSnapshot) for insn in instructions):
        raise TypeError("Mixed symbolic/live instructions_to_copy payload is unsupported")

    snapshots = tuple(instructions)
    return materialize_insn_snapshots(snapshots, safe_ea=mba.entry_ea)


@dataclass
class DeferredGraphModifier:
    """
    Queue-based graph modifier that defers all changes until apply() is called.

    This is the **recommended** modifier for most optimizers. It prevents race
    conditions by separating analysis from modification.

    Basic Usage::

        modifier = DeferredGraphModifier(mba)

        # Queue modifications during analysis (no CFG changes yet)
        modifier.queue_goto_change(block_serial=10, new_target=20)
        modifier.queue_convert_to_goto(block_serial=15, goto_target=25)
        modifier.queue_insn_remove(block_serial=10, insn_ea=0x1234)

        # Apply all modifications atomically
        changes = modifier.apply()

    Integration with Optimizer::

        class MyOptimizer(GenericUnflatteningRule):
            def optimize(self, blk: mblock_t) -> int:
                modifier = DeferredGraphModifier(self.mba)

                # Phase 1: Analysis - collect changes
                for serial in range(self.mba.qty):
                    block = self.mba.get_mblock(serial)
                    if self._needs_redirect(block):
                        modifier.queue_goto_change(
                            block_serial=serial,
                            new_target=self._compute_target(block)
                        )

                # Phase 2: Apply all changes
                return modifier.apply()

    Key Features:
        - Coalesces duplicate modifications automatically
        - Detects conflicting modifications and warns
        - Applies in priority order (block changes before insn removes)
        - Runs mba.optimize_local() and safe_verify() after apply

    See module docstring for complete examples and best practices.
    """
    mba: ida_hexrays.mba_t
    modifications: list[GraphModification] = field(default_factory=list)
    _applied: bool = False
    verify_failed: bool = False
    _pre_snapshot: FlowGraph | None = None
    # Optional event emitter; when None, no events are emitted (zero overhead).
    event_emitter: EventEmitter | None = None
    # Metadata injected by callers so payloads carry rich context.
    _optimizer_name: str = field(default="", init=False)
    _pass_id: int = field(default=0, init=False)
    _session_id: str = field(default="", init=False)

    def reset(self) -> None:
        """Clear all queued modifications."""
        self.modifications.clear()
        self._applied = False

    def configure_events(
        self,
        optimizer_name: str = "",
        pass_id: int = 0,
    ) -> None:
        """Set per-apply context fields injected into event payloads.

        Call this (optionally) before :meth:`apply` so that emitted payloads
        carry useful optimizer/pass metadata.  A fresh ``session_id`` is always
        generated automatically.

        Args:
            optimizer_name: Name of the optimizer/rule that owns this modifier.
            pass_id: Maturity-relative pass counter.
        """
        self._optimizer_name = optimizer_name
        self._pass_id = pass_id
        self._session_id = uuid.uuid4().hex

    def _emit(self, event: DeferredEvent, payload: dict) -> None:
        """Emit *event* with *payload* if an emitter is configured.

        This is a zero-cost guard: when ``self.event_emitter is None`` the
        body is never reached and no dict is constructed by the caller.
        """
        if self.event_emitter is not None:
            self.event_emitter.emit(event, payload)

    def _base_payload(self) -> dict:
        """Build the required-field base for a payload dict."""
        try:
            function_ea: int | None = int(self.mba.entry_ea)
        except Exception:
            function_ea = None
        try:
            maturity: int | None = int(self.mba.maturity)
        except Exception:
            maturity = None
        return {
            "optimizer_name": self._optimizer_name,
            "function_ea": function_ea,
            "maturity": maturity,
            "pass_id": self._pass_id,
            "session_id": self._session_id,
        }

    def _mod_payload(self, mod: GraphModification, mod_index: int | None = None) -> dict:
        """Extend a base payload with modification-specific fields."""
        payload = self._base_payload()
        payload.update({
            "mod_index": mod_index,
            "mod_type": mod.mod_type.name,
            "block_serial": mod.block_serial,
            "new_target": mod.new_target,
            "target_ref_kind": mod.target_ref_kind.name,
            "priority": mod.priority,
            "rule_priority": mod.rule_priority,
            "description": mod.description,
        })
        return payload

    def _infer_target_ref_kind(self, new_target: int | None) -> TargetRefKind:
        """Infer whether *new_target* should track the dynamic STOP block."""
        if new_target is None:
            return TargetRefKind.ABSOLUTE
        try:
            stop_serial = self.mba.qty - 1
            if int(new_target) != stop_serial:
                return TargetRefKind.ABSOLUTE
            stop_blk = self.mba.get_mblock(stop_serial)
            if stop_blk is not None and stop_blk.nsucc() == 0 and stop_blk.tail is None:
                return TargetRefKind.STOP_BLOCK
        except Exception:
            pass
        return TargetRefKind.ABSOLUTE

    def _resolve_target_serial(self, mod: GraphModification) -> int | None:
        """Resolve mod.new_target according to mod.target_ref_kind."""
        if mod.new_target is None:
            return None
        if mod.target_ref_kind == TargetRefKind.STOP_BLOCK:
            return self.mba.qty - 1
        return mod.new_target

    def _is_watched_edge(self, block_serial: int, new_target: int | None) -> bool:
        if new_target is None:
            return False
        watch_edges = _parse_watch_edges_env()
        if not watch_edges:
            return False
        return (int(block_serial), int(new_target)) in watch_edges

    def _debug_dump_block_neighborhood(self, center_serial: int, label: str) -> None:
        """Dump center block and one-hop neighbors with microcode text."""
        try:
            center_blk = self.mba.get_mblock(center_serial)
        except Exception:
            center_blk = None
        logger.warning(
            "DEBUG WATCH %s center=%s",
            label,
            center_serial,
        )
        if center_blk is None:
            logger.warning("DEBUG WATCH block %s not found", center_serial)
            return
        log_block_info(center_blk, logger.warning, ctx=f"DEBUG WATCH {label} center")
        for pred_serial in list(center_blk.predset):
            pred_blk = self.mba.get_mblock(pred_serial)
            log_block_info(
                pred_blk,
                logger.warning,
                ctx=f"DEBUG WATCH {label} predecessor {pred_serial}",
            )
        for succ_serial in list(center_blk.succset):
            succ_blk = self.mba.get_mblock(succ_serial)
            log_block_info(
                succ_blk,
                logger.warning,
                ctx=f"DEBUG WATCH {label} successor {succ_serial}",
            )

    def queue_goto_change(
        self,
        block_serial: int,
        new_target: int,
        description: str = "",
        rule_priority: int = 0,
        target_ref_kind: TargetRefKind | None = None,
    ) -> None:
        """Queue a change to an unconditional goto's destination.

        Args:
            block_serial: Serial number of the block to modify
            new_target: New goto target block serial
            description: Description for logging
            rule_priority: Priority for conflict resolution (higher = wins).
                           Use 100 for proven constant analysis,
                           50 for path-based analysis,
                           0 for default/fallback rules.
        """
        resolved_target_kind = (
            target_ref_kind
            if target_ref_kind is not None
            else self._infer_target_ref_kind(new_target)
        )
        self.modifications.append(GraphModification(
            mod_type=ModificationType.BLOCK_GOTO_CHANGE,
            block_serial=block_serial,
            new_target=new_target,
            priority=10,  # High priority - do block changes first
            description=description or f"goto {block_serial} -> {new_target}",
            rule_priority=rule_priority,
            target_ref_kind=resolved_target_kind,
        ))
        logger.debug(
            "Queued goto change: block %d -> %d (rule_priority=%d)",
            block_serial, new_target, rule_priority
        )
        if self.event_emitter is not None:
            payload = self._mod_payload(self.modifications[-1])
            self._emit(DeferredEvent.DEFERRED_QUEUE_ADDED, payload)
        if self._is_watched_edge(block_serial, new_target):
            logger.warning(
                "DEBUG WATCH enqueue BLOCK_GOTO_CHANGE %d -> %d desc=%s",
                block_serial,
                new_target,
                description,
            )
            self._debug_dump_block_neighborhood(block_serial, "enqueue source")
            self._debug_dump_block_neighborhood(new_target, "enqueue target")

    def queue_conditional_target_change(
        self,
        block_serial: int,
        new_target: int,
        description: str = "",
        target_ref_kind: TargetRefKind | None = None,
    ) -> None:
        """Queue a change to a conditional jump's target."""
        resolved_target_kind = (
            target_ref_kind
            if target_ref_kind is not None
            else self._infer_target_ref_kind(new_target)
        )
        self.modifications.append(GraphModification(
            mod_type=ModificationType.BLOCK_TARGET_CHANGE,
            block_serial=block_serial,
            new_target=new_target,
            priority=10,
            description=description or f"jmp target {block_serial} -> {new_target}",
            target_ref_kind=resolved_target_kind,
        ))
        logger.debug("Queued target change: block %d -> %d", block_serial, new_target)
        if self.event_emitter is not None:
            self._emit(DeferredEvent.DEFERRED_QUEUE_ADDED, self._mod_payload(self.modifications[-1]))

    def queue_convert_to_goto(
        self,
        block_serial: int,
        goto_target: int,
        description: str = "",
        target_ref_kind: TargetRefKind | None = None,
    ) -> None:
        """Queue conversion of a 2-way block to a 1-way goto."""
        resolved_target_kind = (
            target_ref_kind
            if target_ref_kind is not None
            else self._infer_target_ref_kind(goto_target)
        )
        self.modifications.append(GraphModification(
            mod_type=ModificationType.BLOCK_CONVERT_TO_GOTO,
            block_serial=block_serial,
            new_target=goto_target,
            priority=20,  # After simple target changes
            description=description or f"convert {block_serial} to goto {goto_target}",
            target_ref_kind=resolved_target_kind,
        ))
        logger.debug("Queued convert to goto: block %d -> %d", block_serial, goto_target)
        if self.event_emitter is not None:
            self._emit(DeferredEvent.DEFERRED_QUEUE_ADDED, self._mod_payload(self.modifications[-1]))

    def queue_insn_remove(
        self,
        block_serial: int,
        insn_ea: int,
        description: str = "",
    ) -> None:
        """Queue removal of a specific instruction (by EA)."""
        self.modifications.append(GraphModification(
            mod_type=ModificationType.INSN_REMOVE,
            block_serial=block_serial,
            insn_ea=insn_ea,
            priority=1000,  # Very low priority - do last
            description=description or f"remove insn at {hex(insn_ea)} in block {block_serial}",
        ))
        logger.debug("Queued insn remove: block %d, ea=%s", block_serial, hex(insn_ea))
        if self.event_emitter is not None:
            self._emit(DeferredEvent.DEFERRED_QUEUE_ADDED, self._mod_payload(self.modifications[-1]))

    def queue_insn_nop(
        self,
        block_serial: int,
        insn_ea: int,
        description: str = "",
    ) -> None:
        """Queue NOP of a specific instruction (by EA)."""
        self.modifications.append(GraphModification(
            mod_type=ModificationType.INSN_NOP,
            block_serial=block_serial,
            insn_ea=insn_ea,
            priority=900,  # Low priority but before removes
            description=description or f"nop insn at {hex(insn_ea)} in block {block_serial}",
        ))
        logger.debug("Queued insn nop: block %d, ea=%s", block_serial, hex(insn_ea))
        if self.event_emitter is not None:
            self._emit(DeferredEvent.DEFERRED_QUEUE_ADDED, self._mod_payload(self.modifications[-1]))

    def queue_create_and_redirect(
        self,
        source_block_serial: int,
        final_target_serial: int,
        instructions_to_copy: list | tuple,
        is_0_way: bool = False,
        expected_serial: int | None = None,
        description: str = "",
    ) -> None:
        """
        Queue creation of an intermediate block with instruction redirect.

        This creates a new block containing the specified instructions,
        redirects source_block to the new block, and redirects new block
        to final_target.

        Args:
            source_block_serial: Block whose successor will be changed to new block
            final_target_serial: Final target block after the intermediate block
            instructions_to_copy: List of minsn_t or InsnSnapshot to copy to the new block
            is_0_way: If True, new block will be 0-way (no successor)
            description: Optional description for logging
        """
        self.modifications.append(GraphModification(
            mod_type=ModificationType.BLOCK_CREATE_WITH_REDIRECT,
            block_serial=source_block_serial,
            new_target=final_target_serial,  # Used as reference block for insert_nop_blk
            final_target=final_target_serial,
            instructions_to_copy=instructions_to_copy,
            is_0_way=is_0_way,
            expected_serial=expected_serial,
            priority=5,  # Very high priority - create blocks before other changes
            description=description or f"create block after {source_block_serial} -> {final_target_serial}",
        ))
        logger.debug(
            "Queued create_and_redirect: %d -> (new) -> %d with %d instructions",
            source_block_serial, final_target_serial, len(instructions_to_copy)
        )
        if self.event_emitter is not None:
            self._emit(DeferredEvent.DEFERRED_QUEUE_ADDED, self._mod_payload(self.modifications[-1]))

    def queue_create_conditional_redirect(
        self,
        source_blk_serial: int,
        ref_blk_serial: int,
        conditional_target_serial: int,
        fallthrough_target_serial: int,
        expected_conditional_serial: int | None = None,
        expected_fallthrough_serial: int | None = None,
        description: str = "",
    ) -> None:
        """
        Queue creation of a conditional 2-way block with two wired successors.

        This creates a new conditional block by duplicating the reference block,
        then wires it with:
        - Conditional jump target (jcc taken)
        - Fallthrough target (via NOP-goto block for physical adjacency)

        Uses the proven pattern from fix_pred_cond_jump_block.py:
        1. Duplicate the conditional block (preserving tail instruction)
        2. Create a NOP-goto block as fallthrough (IDA requires physical adjacency)
        3. Wire conditional target directly
        4. Redirect source block to the new conditional block

        Args:
            source_blk_serial: Block whose successor will be changed to new block
            ref_blk_serial: Block to copy instructions from (should be conditional)
            conditional_target_serial: Target for jcc taken branch
            fallthrough_target_serial: Target for fallthrough (via NOP-goto)
            expected_conditional_serial: Expected final serial for cloned conditional block
            expected_fallthrough_serial: Expected final serial for NOP fallthrough block
            description: Optional description for logging
        """
        self.modifications.append(GraphModification(
            mod_type=ModificationType.BLOCK_CREATE_WITH_CONDITIONAL_REDIRECT,
            block_serial=source_blk_serial,
            new_target=ref_blk_serial,  # Reference block to copy from
            conditional_target=conditional_target_serial,
            fallthrough_target=fallthrough_target_serial,
            expected_conditional_serial=expected_conditional_serial,
            expected_fallthrough_serial=expected_fallthrough_serial,
            priority=5,  # Very high priority - create blocks before other changes
            description=description or (
                f"create conditional block after {source_blk_serial} "
                f"-> jcc:{conditional_target_serial} / fallthrough:{fallthrough_target_serial}"
            ),
        ))
        logger.debug(
            "Queued create_conditional_redirect: %d -> (new conditional) "
            "-> jcc:%d / fallthrough:%d",
            source_blk_serial, conditional_target_serial, fallthrough_target_serial
        )
        if self.event_emitter is not None:
            self._emit(DeferredEvent.DEFERRED_QUEUE_ADDED, self._mod_payload(self.modifications[-1]))
        if self._is_watched_edge(source_blk_serial, ref_blk_serial):
            logger.warning(
                "DEBUG WATCH enqueue BLOCK_CREATE_WITH_CONDITIONAL_REDIRECT "
                "source=%d ref=%d jcc=%d ft=%d desc=%s",
                source_blk_serial,
                ref_blk_serial,
                conditional_target_serial,
                fallthrough_target_serial,
                description,
            )
            self._debug_dump_block_neighborhood(source_blk_serial, "enqueue source")
            self._debug_dump_block_neighborhood(ref_blk_serial, "enqueue ref-target")

    def queue_duplicate_block(
        self,
        *,
        source_block_serial: int,
        pred_serial: int | None,
        target_serial: int | None = None,
        expected_serial: int | None = None,
        expected_secondary_serial: int | None = None,
        description: str = "",
        rule_priority: int = 0,
    ) -> None:
        """Queue duplication of ``source_block_serial`` and redirect ``pred_serial`` to the clone."""
        self.modifications.append(GraphModification(
            mod_type=ModificationType.BLOCK_DUPLICATE_AND_REDIRECT,
            block_serial=source_block_serial,
            new_target=target_serial,
            via_pred=pred_serial,
            expected_serial=expected_serial,
            expected_secondary_serial=expected_secondary_serial,
            priority=5,
            rule_priority=rule_priority,
            description=description or (
                f"duplicate block src={source_block_serial} pred={pred_serial} "
                f"target={target_serial}"
            ),
        ))
        logger.debug(
            "Queued duplicate_block: src=%d pred=%s target=%s expected=%s secondary=%s",
            source_block_serial,
            pred_serial,
            target_serial,
            expected_serial,
            expected_secondary_serial,
        )
        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_QUEUE_ADDED,
                self._mod_payload(self.modifications[-1]),
            )

    def queue_edge_redirect(
        self,
        src_block: int,
        old_target: int,
        new_target: int,
        via_pred: int | None = None,
        clone_until: int | None = None,
        description: str = "",
        rule_priority: int = 0,
    ) -> None:
        """Queue an edge-level redirect, optionally via predecessor-split cloning.

        When ``via_pred`` is None, delegates to :meth:`queue_goto_change` for
        full backward compatibility.

        When ``via_pred`` is provided, queues an ``EDGE_REDIRECT_VIA_PRED_SPLIT``
        modification: the ``src_block`` will be cloned and the edge from
        ``via_pred`` rewired to the clone, which then targets ``new_target``
        instead of ``old_target``.

        Args:
            src_block: The block to redirect (or clone if via_pred is set).
            old_target: Current successor on src_block being replaced (on clone).
            new_target: New successor target for the clone.
            via_pred: Predecessor whose edge is rewired to the clone. If None,
                      legacy BLOCK_GOTO_CHANGE semantics apply.
            clone_until: Future corridor endpoint (not yet implemented, stub).
            description: Optional logging description.
            rule_priority: Conflict-resolution priority (higher wins).
        """
        if via_pred is None:
            self.queue_goto_change(
                block_serial=src_block,
                new_target=new_target,
                description=description,
                rule_priority=rule_priority,
            )
            return

        self.modifications.append(GraphModification(
            mod_type=ModificationType.EDGE_REDIRECT_VIA_PRED_SPLIT,
            block_serial=src_block,
            new_target=new_target,
            priority=8,
            description=description or (
                f"edge redirect via pred split: pred={via_pred} src={src_block} "
                f"{old_target} -> {new_target}"
            ),
            rule_priority=rule_priority,
            src_block=src_block,
            old_target=old_target,
            via_pred=via_pred,
            clone_until=clone_until,
        ))
        logger.debug(
            "Queued edge_redirect_via_pred_split: pred=%d src=%d old=%d new=%d "
            "(rule_priority=%d)",
            via_pred, src_block, old_target, new_target, rule_priority,
        )
        if self.event_emitter is not None:
            self._emit(DeferredEvent.DEFERRED_QUEUE_ADDED, self._mod_payload(self.modifications[-1]))

    def queue_edge_split_trampoline(
        self,
        *,
        source_block: int,
        via_pred: int,
        old_target: int,
        new_target: int,
        expected_serial: int,
        description: str = "",
        rule_priority: int = 0,
    ) -> None:
        """Queue a finalized edge-split trampoline materialization.

        This is the backend form produced by PatchPlan compilation:
        create one standalone 1-way trampoline block targeting ``new_target``,
        then redirect ``via_pred`` from ``source_block`` to that new block.
        """
        self.modifications.append(GraphModification(
            mod_type=ModificationType.EDGE_SPLIT_TRAMPOLINE,
            block_serial=via_pred,
            new_target=new_target,
            priority=5,
            description=description or (
                f"edge split trampoline: pred={via_pred} src={source_block} "
                f"{old_target}->{new_target} serial={expected_serial}"
            ),
            rule_priority=rule_priority,
            src_block=source_block,
            old_target=old_target,
            via_pred=via_pred,
            expected_serial=expected_serial,
        ))
        logger.debug(
            "Queued edge_split_trampoline: pred=%d src=%d old=%d new=%d serial=%d",
            via_pred,
            source_block,
            old_target,
            new_target,
            expected_serial,
        )
        if self.event_emitter is not None:
            self._emit(DeferredEvent.DEFERRED_QUEUE_ADDED, self._mod_payload(self.modifications[-1]))

    def queue_remove_edge(
        self,
        from_serial: int,
        to_serial: int,
        description: str = "",
    ) -> None:
        """Queue removal of a single edge from *from_serial* to *to_serial*.

        At apply-time the source block is downgraded:
        2-way becomes 1-way (goto to the remaining successor),
        1-way becomes 0-way (goto NOP'd).
        """
        self.modifications.append(GraphModification(
            mod_type=ModificationType.EDGE_REMOVE,
            block_serial=from_serial,
            new_target=to_serial,
            priority=15,  # After goto changes (10) but before convert-to-goto (20)
            description=description or f"remove edge {from_serial}->{to_serial}",
        ))
        logger.debug(
            "Queued edge remove: %d -> %d",
            from_serial,
            to_serial,
        )
        if self.event_emitter is not None:
            self._emit(DeferredEvent.DEFERRED_QUEUE_ADDED, self._mod_payload(self.modifications[-1]))

    def queue_private_terminal_suffix(
        self,
        *,
        anchor_serial: int,
        shared_entry_serial: int,
        return_block_serial: int,
        suffix_serials: tuple[int, ...],
        clone_expected_serials: tuple[int, ...],
        description: str = "",
    ) -> None:
        """Queue cloning of a shared terminal suffix chain for one anchor.

        At apply-time, each block in ``suffix_serials`` is cloned in reverse order,
        the cloned chain is wired (first -> ... -> last with 0 succs), and the
        anchor block is redirected from ``shared_entry_serial`` to the clone of
        the first suffix block.
        """
        self.modifications.append(GraphModification(
            mod_type=ModificationType.PRIVATE_TERMINAL_SUFFIX,
            block_serial=anchor_serial,
            new_target=shared_entry_serial,
            priority=12,  # After BLOCK_GOTO_CHANGE (10) so anchors already point to shared_entry
            description=description or (
                f"private terminal suffix anchor={anchor_serial} "
                f"shared_entry={shared_entry_serial} return={return_block_serial} "
                f"suffix={suffix_serials}"
            ),
            suffix_serials=suffix_serials,
            clone_expected_serials=clone_expected_serials,
        ))
        logger.debug(
            "Queued private_terminal_suffix: anchor=%d shared_entry=%d return=%d suffix=%s expected=%s",
            anchor_serial,
            shared_entry_serial,
            return_block_serial,
            suffix_serials,
            clone_expected_serials,
        )
        if self.event_emitter is not None:
            self._emit(DeferredEvent.DEFERRED_QUEUE_ADDED, self._mod_payload(self.modifications[-1]))

    def queue_private_terminal_suffix_group(
        self,
        *,
        anchors: tuple[int, ...],
        shared_entry_serial: int,
        return_block_serial: int,
        suffix_serials: tuple[int, ...],
        per_anchor_clone_expected_serials: tuple[tuple[int, ...], ...],
        description: str = "",
    ) -> None:
        """Queue atomic cloning of a shared terminal suffix chain for multiple anchors.

        At apply-time, each anchor gets its own private copy of the suffix
        chain.  All clones are created in one pass and STOP is relocated once,
        avoiding serial drift from sequential per-anchor application.
        """
        self.modifications.append(GraphModification(
            mod_type=ModificationType.PRIVATE_TERMINAL_SUFFIX_GROUP,
            block_serial=anchors[0],  # primary block for logging
            new_target=shared_entry_serial,
            priority=12,
            description=description or (
                f"private terminal suffix group anchors={anchors} "
                f"shared_entry={shared_entry_serial} return={return_block_serial}"
            ),
            suffix_serials=suffix_serials,
            anchors=anchors,
            per_anchor_clone_expected_serials=per_anchor_clone_expected_serials,
        ))
        logger.debug(
            "Queued private_terminal_suffix_group: anchors=%s shared_entry=%d return=%d suffix=%s",
            anchors,
            shared_entry_serial,
            return_block_serial,
            suffix_serials,
        )
        if self.event_emitter is not None:
            self._emit(DeferredEvent.DEFERRED_QUEUE_ADDED, self._mod_payload(self.modifications[-1]))

    def queue_direct_terminal_lowering_group(
        self,
        *,
        shared_entry_serial: int,
        return_block_serial: int,
        suffix_serials: tuple[int, ...],
        sites: tuple,
        description: str = "",
    ) -> None:
        """Queue grouped direct terminal lowering for multiple anchors.

        Each site specifies a lowering kind (CLONE_MATERIALIZER, RETURN_CONST, etc.)
        and the backend creates per-anchor private return materializers.
        """
        self.modifications.append(GraphModification(
            mod_type=ModificationType.DIRECT_TERMINAL_LOWERING_GROUP,
            block_serial=sites[0].anchor_serial if sites else 0,
            new_target=shared_entry_serial,
            priority=12,
            suffix_serials=suffix_serials,
            sites=sites,
            description=description or (
                f"direct terminal lowering group "
                f"shared_entry={shared_entry_serial} return={return_block_serial} "
                f"sites={len(sites)}"
            ),
        ))
        logger.debug(
            "Queued direct_terminal_lowering_group: shared_entry=%d return=%d sites=%d",
            shared_entry_serial,
            return_block_serial,
            len(sites),
        )
        if self.event_emitter is not None:
            self._emit(DeferredEvent.DEFERRED_QUEUE_ADDED, self._mod_payload(self.modifications[-1]))

    def has_modifications(self) -> bool:
        """Check if there are any queued modifications."""
        return len(self.modifications) > 0

    def _restore_from_snapshot(self, snapshot: FlowGraph) -> bool:
        """Restore MBA topology from a FlowGraph snapshot.

        Best-effort restoration of block topology (edges, types, flags).
        Instruction content restoration is not guaranteed.

        Note: Blocks created during failed modifications (serials beyond
        the snapshot) are not removed. Callers should run mba_deep_cleaning()
        after failed rollback if orphaned blocks are suspected.

        Args:
            snapshot: Pre-modification snapshot to restore from.

        Returns:
            True if restoration succeeded and mba.verify() passed.
        """
        if snapshot is None:
            logger.warning("Cannot restore from None snapshot")
            return False

        logger.info("Restoring MBA topology from snapshot (nblocks=%d)", snapshot.num_blocks)

        # Restore block topology: iterate over snapshot blocks and rewire edges
        for serial, snap_blk in snapshot.blocks.items():
            blk = self.mba.get_mblock(serial)
            if blk is None:
                logger.warning("Block %d not found in MBA during restoration", serial)
                continue

            # Compute what needs to change: old edges (current state) vs new edges (snapshot state)
            current_succs = [blk.succset[i] for i in range(blk.succset.size())]
            target_succs = list(snap_blk.succs)

            # Skip if already correct
            if current_succs == target_succs and blk.type == snap_blk.block_type:
                continue

            # Compute edges to remove and add
            old_succs = [s for s in current_succs if s not in target_succs]
            new_succs = [s for s in target_succs if s not in current_succs]

            if logger.debug_on:
                logger.debug(
                    "Restoring block %d: type %d->%d, succs %s->%s",
                    serial, blk.type, snap_blk.block_type, current_succs, target_succs
                )

            # Restore block type and flags directly (before _rewire_edge)
            # CRITICAL FIX: _rewire_edge does OR for flags (blk.flags |= new_flags),
            # but rollback requires full replacement
            blk.type = snap_blk.block_type
            blk.flags = snap_blk.flags

            # Use _rewire_edge helper to update topology only
            try:
                _rewire_edge(
                    blk,
                    old_succs=old_succs,
                    new_succs=new_succs,
                    new_block_type=None,  # Already set above
                    new_flags=None,       # Already set above
                    verify=False,  # Defer verify until all blocks are restored
                )
            except Exception as e:
                logger.error("Failed to restore block %d: %s", serial, e)
                return False

        # Mark chains dirty after restoration
        self.mba.mark_chains_dirty()

        # Verify restoration
        try:
            self.mba.verify(True)
            logger.info("MBA topology restored successfully from snapshot")
            return True
        except RuntimeError as e:
            logger.error("MBA verify failed after snapshot restoration: %s", e)
            return False

    def coalesce(self) -> int:
        """
        Coalesce queued modifications to remove duplicates and optimize the queue.

        This method:
        1. Removes exact duplicate modifications (same type, block_serial, new_target)
        2. Detects and warns about conflicting modifications for the same block
        3. For BLOCK_CREATE_WITH_REDIRECT: keeps only the first modification per source block

        Returns:
            Number of modifications removed.
        """
        if not self.modifications:
            return 0

        if self.event_emitter is not None:
            self._emit(DeferredEvent.DEFERRED_COALESCE_STARTED, {
                **self._base_payload(),
                "queue_size": len(self.modifications),
            })

        original_count = len(self.modifications)

        # Track seen modifications by (mod_type, block_serial, new_target) for deduplication
        seen_keys: set[tuple] = set()
        # Track blocks that have been modified to detect conflicts
        block_modifications: dict[int, list[GraphModification]] = {}

        unique_modifications = []

        for mod in self.modifications:
            # Create a key for deduplication
            # For BLOCK_CREATE_WITH_REDIRECT, we key by (type, source_block, target)
            # since multiple redirects to different targets would conflict
            if mod.mod_type == ModificationType.BLOCK_CREATE_WITH_REDIRECT:
                key = (mod.mod_type, mod.block_serial, mod.new_target, mod.target_ref_kind)
            elif mod.mod_type == ModificationType.BLOCK_CREATE_WITH_CONDITIONAL_REDIRECT:
                key = (mod.mod_type, mod.block_serial, mod.new_target,
                       mod.conditional_target, mod.fallthrough_target, mod.target_ref_kind)
            elif mod.mod_type == ModificationType.BLOCK_DUPLICATE_AND_REDIRECT:
                key = (
                    mod.mod_type,
                    mod.block_serial,
                    mod.via_pred,
                    mod.new_target,
                    mod.expected_serial,
                    mod.expected_secondary_serial,
                )
            elif mod.mod_type in (
                ModificationType.EDGE_REDIRECT_VIA_PRED_SPLIT,
                ModificationType.EDGE_SPLIT_TRAMPOLINE,
            ):
                key = (mod.mod_type, mod.src_block, mod.old_target, mod.via_pred, mod.new_target)
            else:
                key = (mod.mod_type, mod.block_serial, mod.new_target, mod.target_ref_kind)

            if key in seen_keys:
                logger.debug(
                    "Removing duplicate modification: %s block=%d target=%s",
                    mod.mod_type.name, mod.block_serial, mod.new_target
                )
                continue

            seen_keys.add(key)

            # Track all modifications per block for conflict detection
            if mod.block_serial not in block_modifications:
                block_modifications[mod.block_serial] = []
            block_modifications[mod.block_serial].append(mod)

            unique_modifications.append(mod)

        # Detect and resolve conflicting modifications for the same block
        for block_serial, mods in block_modifications.items():
            if len(mods) > 1:
                # Check if they're the same type with different targets (conflict)
                unique_types = set(m.mod_type for m in mods)

                # Same type, different targets = conflict - resolve by rule_priority
                for mod_type in unique_types:
                    if mod_type in (
                        ModificationType.EDGE_REDIRECT_VIA_PRED_SPLIT,
                        ModificationType.EDGE_SPLIT_TRAMPOLINE,
                    ):
                        continue  # Handled by edge-specific conflict pass below
                    same_type_mods = [m for m in mods if m.mod_type == mod_type]
                    if len(same_type_mods) > 1:
                        targets = [(m.new_target, m.target_ref_kind) for m in same_type_mods]
                        if len(set(targets)) > 1:
                            # CONFLICT: Multiple modifications with different targets
                            # Resolve by keeping only the highest rule_priority modification
                            winner = max(same_type_mods, key=lambda m: m.rule_priority)
                            losers = [m for m in same_type_mods if m != winner]

                            logger.warning(
                                "CONFLICT RESOLVED: Block %d - keeping priority=%d (target=%d), "
                                "discarding %s",
                                block_serial,
                                winner.rule_priority,
                                winner.new_target,
                                [(m.rule_priority, m.new_target, m.target_ref_kind.name) for m in losers]
                            )

                            # Remove losers from unique_modifications
                            for loser in losers:
                                if loser in unique_modifications:
                                    unique_modifications.remove(loser)

        # Resolve mixed-type terminal rewrites for the same source block.
        # A single block should not receive multiple competing edge rewrites
        # (e.g., CREATE_WITH_REDIRECT + GOTO_CHANGE), because that can strand
        # newly-created blocks and poison MBA verify.
        # EDGE_REDIRECT_VIA_PRED_SPLIT is intentionally excluded here: its
        # conflict resolution is keyed by (src_block, old_target, via_pred) and
        # is handled by the edge-type-specific pass above.  Including it in the
        # per-block terminal pass would collapse two redirects that share the
        # same src_block but differ only in via_pred — which is legitimate.
        terminal_mod_types = {
            ModificationType.BLOCK_GOTO_CHANGE,
            ModificationType.BLOCK_TARGET_CHANGE,
            ModificationType.BLOCK_CONVERT_TO_GOTO,
            ModificationType.BLOCK_CREATE_WITH_REDIRECT,
            ModificationType.BLOCK_CREATE_WITH_CONDITIONAL_REDIRECT,
            ModificationType.BLOCK_DUPLICATE_AND_REDIRECT,
            ModificationType.EDGE_SPLIT_TRAMPOLINE,
            ModificationType.EDGE_REMOVE,
        }
        terminal_type_rank = {
            ModificationType.BLOCK_GOTO_CHANGE: 1,
            ModificationType.BLOCK_TARGET_CHANGE: 2,
            ModificationType.BLOCK_CONVERT_TO_GOTO: 3,
            ModificationType.BLOCK_CREATE_WITH_REDIRECT: 4,
            ModificationType.BLOCK_CREATE_WITH_CONDITIONAL_REDIRECT: 5,
            ModificationType.BLOCK_DUPLICATE_AND_REDIRECT: 6,
            ModificationType.EDGE_SPLIT_TRAMPOLINE: 7,
            ModificationType.EDGE_REMOVE: 8,
            # EDGE_REDIRECT_VIA_PRED_SPLIT is intentionally absent: it is not
            # in terminal_mod_types (it executes via a separate code path in
            # apply_modifications) so ranking it here would cause it to be
            # incorrectly processed by the terminal-type conflict pass.
        }

        # Edge-type conflict resolution: for EDGE_REDIRECT_VIA_PRED_SPLIT,
        # group by (src_block, old_target, via_pred) and keep highest rule_priority.
        # This must run BEFORE the general terminal-type pass below so that survivors
        # are correctly evaluated in the mixed-type pass.
        for edge_type in (
            ModificationType.EDGE_REDIRECT_VIA_PRED_SPLIT,
            ModificationType.EDGE_SPLIT_TRAMPOLINE,
        ):
            edge_mods = [m for m in unique_modifications if m.mod_type == edge_type]
            if not edge_mods:
                continue
            edge_groups: dict[tuple, list[GraphModification]] = {}
            for em in edge_mods:
                group_key = (em.src_block, em.old_target, em.via_pred)
                edge_groups.setdefault(group_key, []).append(em)
            for group_key, group_mods in edge_groups.items():
                if len(group_mods) <= 1:
                    continue
                targets = {m.new_target for m in group_mods}
                if len(targets) <= 1:
                    continue
                # Conflict: same (src, old, via_pred) but different new_target
                winner = max(group_mods, key=lambda m: m.rule_priority)
                losers = [m for m in group_mods if m != winner]
                logger.warning(
                    "EDGE CONFLICT RESOLVED: type=%s src=%d old=%d via_pred=%d - keeping "
                    "new_target=%d (rule_priority=%d), discarding %s",
                    edge_type.name,
                    group_key[0], group_key[1], group_key[2],
                    winner.new_target, winner.rule_priority,
                    [(m.rule_priority, m.new_target) for m in losers],
                )
                for loser in losers:
                    if loser in unique_modifications:
                        unique_modifications.remove(loser)

        remaining_by_block: dict[int, list[GraphModification]] = {}
        for mod in unique_modifications:
            remaining_by_block.setdefault(mod.block_serial, []).append(mod)

        for block_serial, mods in remaining_by_block.items():
            terminal_mods = [m for m in mods if m.mod_type in terminal_mod_types]
            if len(terminal_mods) <= 1:
                continue

            winner = max(
                terminal_mods,
                key=lambda m: (
                    m.rule_priority,
                    terminal_type_rank.get(m.mod_type, 0),
                    -m.priority,
                ),
            )
            losers = [m for m in terminal_mods if m != winner]
            logger.warning(
                "TERMINAL CONFLICT RESOLVED: Block %d - keeping %s "
                "(rule_priority=%d target=%s), discarding %s",
                block_serial,
                winner.mod_type.name,
                winner.rule_priority,
                winner.new_target,
                [
                    (m.mod_type.name, m.rule_priority, m.new_target)
                    for m in losers
                ],
            )
            for loser in losers:
                if loser in unique_modifications:
                    unique_modifications.remove(loser)

        removed_count = original_count - len(unique_modifications)
        if removed_count > 0:
            logger.info(
                "Coalesced modifications: removed %d duplicates/conflicts (%d -> %d)",
                removed_count, original_count, len(unique_modifications)
            )

        self.modifications = unique_modifications
        if self.event_emitter is not None:
            self._emit(DeferredEvent.DEFERRED_COALESCE_FINISHED, {
                **self._base_payload(),
                "queue_size": len(self.modifications),
                "removed_count": removed_count,
            })
        return removed_count

    def _repair_wrong_successors(self) -> int:
        """Scan all blocks and fix inconsistent succset/predset entries.

        INTERR 50860 ("wrong successor set") can be raised by ``mba.verify()``
        if the successor set stored in ``blk.succset`` does not match what the
        tail instruction actually implies.  This can happen when earlier passes
        or IDA's own normalisation leave block 210 (or any block) with stale
        edge bookkeeping *before* we attempt our deferred modifications.

        The method recomputes the expected successor set from the tail
        instruction for every block:

        * ``m_goto`` (opcode 55): ``{tail.l.b}``
        * ``m_jcnd`` / conditional: ``{blk.serial + 1, tail.d.b}``
        * ``m_jtbl`` (switch): all ``cases.targets`` entries
        * Empty block / exit (no tail or BLT_STOP/BLT_0WAY): ``{}``

        If the stored ``succset`` differs from the expected set, the method
        updates ``succset`` and mirrors the change into the affected blocks'
        ``predset``.

        Returns:
            Number of blocks whose successor sets were repaired.
        """
        try:
            import ida_hexrays as _ihr
        except ImportError:
            logger.debug("_repair_wrong_successors: ida_hexrays not available, skipping")
            return 0

        repaired = 0
        qty = self.mba.qty
        for i in range(qty):
            blk = self.mba.get_mblock(i)
            if blk is None:
                continue

            # Compute expected successor set from tail instruction
            tail = blk.tail

            if tail is None:
                if blk.type == 3:  # BLT_NWAY: switch dispatch node, skip  --  edges preserved by deferred mods
                    continue
                # IDA verify.cpp: for null-tail blocks, outs = {serial+1} if ns>0, else {}
                # For BLT_1WAY (type 1): ns = 1
                # For BLT_2WAY (type 2): ns = 2
                # For BLT_STOP/0WAY (type 0): ns = 0
                # ns_from_type maps type -> fixed ns
                raw_succset_null = [int(blk.succset[j]) for j in range(blk.succset.size())]
                current_null = set(raw_succset_null)
                ns = {0: 0, 1: 1, 2: 2}.get(blk.type, 0)
                expected_null = {blk.serial + 1} if ns > 0 else set()

                if current_null != expected_null and current_null:
                    # Only repair when the block already has successors (current_null
                    # is non-empty). If current_null is empty the block may be a
                    # terminal/disconnected block that IDA manages  --  adding edges
                    # speculatively can corrupt the MBA further.
                    # Repair: transition succset from current to expected_null
                    for old_succ in sorted(current_null - expected_null):
                        old_blk = self.mba.get_mblock(old_succ)
                        if old_blk is not None:
                            new_preds = [
                                int(old_blk.predset[k])
                                for k in range(old_blk.predset.size())
                                if int(old_blk.predset[k]) != blk.serial
                            ]
                            old_blk.predset.clear()
                            for p in new_preds:
                                old_blk.predset.push_back(p)
                    for new_succ in sorted(expected_null - current_null):
                        if new_succ < self.mba.qty:
                            succ_blk = self.mba.get_mblock(new_succ)
                            if succ_blk is not None:
                                succ_blk.predset.push_back(blk.serial)
                    blk.succset.clear()
                    for s in sorted(expected_null):
                        blk.succset.push_back(s)
                    # If type=BLT_2WAY but repaired to 1 successor, change type to 1WAY
                    if blk.type == 2 and len(expected_null) == 1:
                        blk.type = 1
                    repaired += 1
                    logger.warning(
                        "blk[%d] -- NULL-tail wrong succset %s, expected %s -- repaired",
                        blk.serial, sorted(current_null), sorted(expected_null)
                    )
                continue

            expected: set[int] = set()

            if blk.type in (ida_hexrays.BLT_STOP, ida_hexrays.BLT_0WAY):
                # Exit / noret block: no successors expected
                expected = set()
            elif tail.opcode == _ihr.m_goto:
                # Unconditional goto: successor is tail.l.b (mop_b operand)
                if tail.l is not None and tail.l.t == _ihr.mop_b:
                    expected = {int(tail.l.b)}
            elif tail.opcode == _ihr.m_jcnd:
                # Conditional branch: fallthrough = serial+1, taken = tail.d.b
                if tail.d is not None and tail.d.t == _ihr.mop_b:
                    next_serial = blk.serial + 1
                    if next_serial < qty:
                        expected = {next_serial, int(tail.d.b)}
                    else:
                        expected = {int(tail.d.b)}
            elif tail.opcode == _ihr.m_jtbl:
                # Switch: all mcases targets
                if (tail.r is not None and tail.r.t == _ihr.mop_c
                        and tail.r.c is not None):
                    cases = tail.r.c
                    targets_vec = cases.targets
                    n = targets_vec.size()
                    expected = {int(targets_vec[j]) for j in range(n)}
            # For all other opcodes (calls, assignments, etc.) we leave
            # expected as set()  --  non-jump tails imply fallthrough to serial+1.
            # However we do NOT repair those here to avoid false positives on
            # instructions that don't encode flow in the tail.

            # Compare against stored succset
            raw_succset = [int(blk.succset[j]) for j in range(blk.succset.size())]
            current = set(raw_succset)

            # Diagnostic: log every block with a tail at DEBUG level
            logger.debug(
                "blk[%d] type=%d tail_opcode=%d raw_succset=%s expected=%s",
                blk.serial, blk.type, tail.opcode, raw_succset, sorted(expected),
            )

            # Extra diagnostics for block 210 (INTERR 50860 target) at WARNING
            if blk.serial == 210:
                logger.warning(
                    "blk[210] raw_succset=%s set(raw)=%s expected=%s "
                    "has_duplicates=%s len_raw=%d",
                    raw_succset, sorted(current), sorted(expected),
                    len(raw_succset) != len(current), len(raw_succset),
                )

            if current == expected:
                continue  # Nothing to fix

            # Only repair if we computed a concrete expectation.  If expected
            # is empty it means we could not parse the tail target (e.g. a
            # goto with a non-mop_b operand, or an unrecognised opcode)  --  in
            # that case do NOT remove legitimate edges.
            if not expected:
                logger.debug(
                    "_repair_wrong_successors: block %d has tail opcode %d "
                    "with non-empty succset %s -- skipping (could not determine expected successors)",
                    blk.serial, tail.opcode if tail is not None else -1, sorted(current),
                )
                continue

            logger.warning(
                "_repair_wrong_successors: block %d succset %s != expected %s "
                "(tail opcode %s) -- repairing",
                blk.serial,
                sorted(current),
                sorted(expected),
                tail.opcode if tail is not None else "None",
            )

            # ── Update succset on this block ──────────────────────────────────
            # Remove stale successors from their predsets
            for stale in current - expected:
                stale_blk = self.mba.get_mblock(stale)
                if stale_blk is None:
                    continue
                new_preds = [
                    int(stale_blk.predset[k])
                    for k in range(stale_blk.predset.size())
                    if int(stale_blk.predset[k]) != blk.serial
                ]
                stale_blk.predset.clear()
                for p in new_preds:
                    stale_blk.predset.push_back(p)

            # Rebuild succset
            blk.succset.clear()
            for s in sorted(expected):
                blk.succset.push_back(s)

            # Add this block as predecessor of any newly-added successors
            for added in expected - current:
                added_blk = self.mba.get_mblock(added)
                if added_blk is None:
                    continue
                existing_preds = {
                    int(added_blk.predset[k])
                    for k in range(added_blk.predset.size())
                }
                if blk.serial not in existing_preds:
                    added_blk.predset.push_back(blk.serial)

            repaired += 1

        if repaired:
            logger.warning(
                "_repair_wrong_successors: repaired %d block(s) with inconsistent "
                "successor sets",
                repaired,
            )
        return repaired


    def apply(
        self,
        run_optimize_local: bool = True,
        run_deep_cleaning: bool = False,
        verify_each_mod: bool = False,
        rollback_on_verify_failure: bool = False,
        continue_on_verify_failure: bool = False,
        defer_post_apply_maintenance: bool = False,
        enable_snapshot_rollback: bool = False,
        post_apply_hook: Callable[[], None] | None = None,
    ) -> int:
        """
        Apply all queued modifications in priority order.

        Args:
            run_optimize_local: If True, call mba.optimize_local(0) after changes
            run_deep_cleaning: If True, run mba_deep_cleaning after changes
            verify_each_mod: If True, run safe_verify() after each successful
                modification and abort immediately on first verify failure.
            rollback_on_verify_failure: If True and incremental verify fails,
                attempt to roll back that single modification (best effort for
                reversible modification types).
            continue_on_verify_failure: If True, and rollback succeeds plus
                verify passes after rollback, skip the bad modification and
                continue applying later queued modifications.
            defer_post_apply_maintenance: If True, return immediately after
                applying queued modifications (and marking chains dirty),
                skipping cleanup/verify so callers can perform custom
                canonicalization first.
            enable_snapshot_rollback: If True, capture a pre-modification snapshot
                and restore from it on post-apply verify failure. This provides
                full-topology rollback at the cost of snapshot overhead.
            post_apply_hook: Optional callback executed after queued
                modifications are applied and before cleanup/verify. Use this
                to run post-apply canonicalization inside the same transactional
                boundary as deferred rewrites.

        Returns:
            Number of successful modifications applied.
        """
        if self._applied:
            logger.warning("DeferredGraphModifier.apply() called twice")
            return 0

        if not self.modifications:
            logger.debug("No modifications to apply")
            return 0

        # Pre-apply successor repair: if the MBA already has an inconsistent
        # succset (INTERR 50860) before we touch it  --  e.g. block 210 at
        # MMAT_GLBOPT1  --  verify_each_mod=True would abort all 74 modifications
        # on the very first check.  We detect and repair that upfront so the
        # deferred batch can proceed cleanly.
        try:
            safe_verify(
                self.mba,
                "before deferred modifications (pre-apply check)",
                logger_func=logger.debug,
                capture_metadata={
                    "phase": "pre_apply_verify",
                    "queued_modifications": len(self.modifications),
                },
            )
            if _env_flag("D810_DEFERRED_PREVERIFY"):
                logger.warning("DEBUG: pre-apply verify passed")
        except RuntimeError:
            logger.warning(
                "Pre-apply verify failed (likely stale succset from earlier pass); "
                "attempting _repair_wrong_successors before deferred apply"
            )
            repaired = self._repair_wrong_successors()
            if repaired > 0:
                # Re-verify after repair
                try:
                    safe_verify(
                        self.mba,
                        "after pre-apply successor repair",
                        logger_func=logger.warning,
                        capture_metadata={
                            "phase": "pre_apply_repair_verify",
                            "repaired_blocks": repaired,
                            "queued_modifications": len(self.modifications),
                        },
                    )
                    logger.warning(
                        "Pre-apply repair succeeded (%d block(s)); "
                        "proceeding with %d deferred modifications",
                        repaired, len(self.modifications),
                    )
                except RuntimeError:
                    logger.error(
                        "Pre-apply verify still failing after %d repair(s); "
                        "aborting deferred apply to protect MBA integrity",
                        repaired,
                    )
                    self.verify_failed = True
                    self._applied = True
                    return 0
            else:
                logger.error(
                    "Pre-apply verify failed and _repair_wrong_successors "
                    "found nothing to fix; proceeding optimistically "
                    "(verify_each_mod=%s)  --  disabling per-mod verify to avoid "
                    "spurious abort on pre-existing stale succset",
                    verify_each_mod,
                )
                # The pre-existing stale succset (e.g. block 210) is NOT caused
                # by our deferred mods.  Disable per-modification verification
                # so the batch can proceed without aborting on the first check.
                verify_each_mod = False

        # Capture pre-modification snapshot if enabled
        if enable_snapshot_rollback:
            logger.info("Capturing pre-modification snapshot for rollback")
            try:
                self._pre_snapshot = lift(self.mba)
                logger.debug(
                    "Snapshot captured: %d blocks, entry=%d",
                    self._pre_snapshot.num_blocks,
                    self._pre_snapshot.entry_serial,
                )
            except Exception as e:
                logger.error("Failed to capture pre-modification snapshot: %s", e)
                logger.warning(
                    "Snapshot rollback disabled: failed to capture snapshot, "
                    "proceeding without rollback protection"
                )
                # Continue without snapshot - best effort
                self._pre_snapshot = None

        # Coalesce duplicates and detect conflicts before applying
        self.coalesce()

        if not self.modifications:
            logger.debug("No modifications after coalescing")
            return 0

        if _env_flag("D810_DEFERRED_VERIFY_EACH"):
            verify_each_mod = True
            if _env_flag("D810_DEFERRED_ROLLBACK_ON_VERIFY_FAILURE"):
                rollback_on_verify_failure = True
            if _env_flag("D810_DEFERRED_CONTINUE_ON_VERIFY_FAILURE"):
                continue_on_verify_failure = True
            logger.warning(
                "DEBUG: forcing verify_each_mod=%s rollback_on_verify_failure=%s "
                "continue_on_verify_failure=%s",
                verify_each_mod,
                rollback_on_verify_failure,
                continue_on_verify_failure,
            )

        # Sort by priority (lower = earlier)
        sorted_mods = sorted(self.modifications, key=lambda m: m.priority)

        # Debug knob: limit number of deferred modifications applied in this batch.
        # Useful for bisecting CFG corruption/segfault sources without changing
        # optimizer logic. Ignored unless explicitly set to a positive integer.
        max_apply_env = os.environ.get("D810_DEFERRED_MAX_APPLY", "").strip()
        if max_apply_env:
            try:
                max_apply = int(max_apply_env, 10)
            except ValueError:
                max_apply = 0
            if max_apply > 0 and max_apply < len(sorted_mods):
                logger.warning(
                    "DEBUG: Limiting deferred apply to first %d/%d modifications "
                    "(D810_DEFERRED_MAX_APPLY)",
                    max_apply,
                    len(sorted_mods),
                )
                sorted_mods = sorted_mods[:max_apply]

        # Debug knob: skip specific edge rewrites, e.g. "381:382,100:42"
        # in D810_DEFERRED_SKIP_EDGES. Only affects BLOCK_* modifications
        # with both source block and new_target populated.
        skip_edges_env = os.environ.get("D810_DEFERRED_SKIP_EDGES", "").strip()
        if skip_edges_env:
            skip_edges: set[tuple[int, int]] = set()
            for token in skip_edges_env.split(","):
                token = token.strip()
                if not token or ":" not in token:
                    continue
                lhs, rhs = token.split(":", 1)
                try:
                    skip_edges.add((int(lhs, 10), int(rhs, 10)))
                except ValueError:
                    continue
            if skip_edges:
                filtered_mods = []
                skipped = 0
                for mod in sorted_mods:
                    if mod.new_target is None:
                        filtered_mods.append(mod)
                        continue
                    edge_key = (int(mod.block_serial), int(mod.new_target))
                    if edge_key in skip_edges:
                        skipped += 1
                        continue
                    filtered_mods.append(mod)
                if skipped:
                    logger.warning(
                        "DEBUG: Skipped %d deferred edge rewrite(s) via "
                        "D810_DEFERRED_SKIP_EDGES: %s",
                        skipped,
                        sorted(skip_edges),
                    )
                sorted_mods = filtered_mods

        sorted_mods, pre_rejected_create = self._pre_reject_create_and_redirects(sorted_mods)
        sorted_mods, pre_rejected_duplicate = self._pre_reject_duplicate_blocks(sorted_mods)
        sorted_mods, pre_rejected_trampolines = self._pre_reject_edge_split_trampolines(
            sorted_mods
        )
        pre_rejected = (
            pre_rejected_create
            + pre_rejected_duplicate
            + pre_rejected_trampolines
        )
        total_mod_count = len(sorted_mods) + pre_rejected

        logger.info("Applying %d queued graph modifications", total_mod_count)

        if self.event_emitter is not None:
            self._emit(DeferredEvent.DEFERRED_APPLY_STARTED, {
                **self._base_payload(),
                "modification_count": total_mod_count,
            })

        # Log all queued modifications before applying
        logger.info("=== QUEUED MODIFICATIONS (sorted by priority) ===")
        for i, mod in enumerate(sorted_mods):
            blk = self.mba.get_mblock(mod.block_serial)
            logger.info(
                "  [%d] %s (priority=%d) target_blk=%d new_target=%s ref=%s",
                i, mod.mod_type.name, mod.priority, mod.block_serial, mod.new_target,
                mod.target_ref_kind.name,
            )
            logger.info("      BEFORE: %s", _format_block_info(blk))
            if mod.new_target is not None:
                target_blk = self.mba.get_mblock(mod.new_target)
                logger.info("      TARGET: %s", _format_block_info(target_blk))

        successful = 0
        failed = pre_rejected
        rolled_back = 0
        recent_modifications: list[dict] = []

        for i, mod in enumerate(sorted_mods):
            effective_new_target = self._resolve_target_serial(mod)
            if effective_new_target != mod.new_target:
                logger.debug(
                    "Resolved dynamic target for mod[%d] %s: %s -> %s",
                    i,
                    mod.mod_type.name,
                    mod.new_target,
                    effective_new_target,
                )
                mod.new_target = effective_new_target
            blk = self.mba.get_mblock(mod.block_serial)
            logger.info("--- Applying [%d]: %s ---", i, mod.description)
            logger.info("    BEFORE: %s", _format_block_info(blk))

            if self._is_watched_edge(mod.block_serial, mod.new_target):
                logger.warning(
                    "DEBUG WATCH apply[%d] %s src=%d dst=%s",
                    i,
                    mod.mod_type.name,
                    mod.block_serial,
                    mod.new_target,
                )
                self._debug_dump_block_neighborhood(mod.block_serial, f"pre-apply[{i}] source")
                if mod.new_target is not None:
                    self._debug_dump_block_neighborhood(mod.new_target, f"pre-apply[{i}] target")
            source_before_snapshot = snapshot_block_for_capture(blk)
            target_before_snapshot = None
            if mod.new_target is not None:
                target_before_snapshot = snapshot_block_for_capture(
                    self.mba.get_mblock(mod.new_target)
                )

            rollback_plan = None
            if verify_each_mod and rollback_on_verify_failure:
                rollback_plan = self._prepare_rollback(mod)

            if self.event_emitter is not None:
                self._emit(DeferredEvent.DEFERRED_MOD_STARTED, self._mod_payload(mod, i))

            try:
                result = self._apply_single(mod)
                # Re-fetch block after modification
                blk_after = self.mba.get_mblock(mod.block_serial)
                logger.info("    AFTER:  %s", _format_block_info(blk_after))
                source_after_snapshot = snapshot_block_for_capture(blk_after)
                target_after_snapshot = None
                if mod.new_target is not None:
                    target_after_snapshot = snapshot_block_for_capture(
                        self.mba.get_mblock(mod.new_target)
                    )

                current_mod_trace = {
                    "index": i,
                    "description": mod.description,
                    "mod_type": mod.mod_type.name,
                    "priority": mod.priority,
                    "rule_priority": mod.rule_priority,
                    "block_serial": mod.block_serial,
                    "new_target": mod.new_target,
                    "before": source_before_snapshot,
                    "after": source_after_snapshot,
                    "target_before": target_before_snapshot,
                    "target_after": target_after_snapshot,
                }
                recent_modifications.append(current_mod_trace)
                if len(recent_modifications) > _MAX_CAPTURE_HISTORY:
                    recent_modifications.pop(0)

                if result:
                    # Optional incremental verification mode: fail fast on the
                    # first bad mutation instead of discovering corruption only
                    # after a large deferred batch is applied.
                    if verify_each_mod:
                        capture_blocks = _collect_capture_blocks(
                            source_before_snapshot,
                            source_after_snapshot,
                            target_before_snapshot,
                            target_after_snapshot,
                        )
                        capture_metadata = {
                            "phase": "incremental_verify",
                            "modification": current_mod_trace,
                            "recent_modifications": list(recent_modifications),
                        }
                        try:
                            safe_verify(
                                self.mba,
                                f"after deferred modification [{i}] {mod.description}",
                                logger_func=logger.error,
                                capture_blocks=capture_blocks,
                                capture_metadata=capture_metadata,
                            )
                        except RuntimeError:
                            failed += 1
                            logger.warning("    RESULT: VERIFY FAILED")
                            if self.event_emitter is not None:
                                _vp = self._mod_payload(mod, i)
                                _vp["result"] = "verify_failed"
                                self._emit(DeferredEvent.DEFERRED_VERIFY_FAILED, _vp)
                            rolled_back_ok = False

                            if rollback_plan is not None:
                                rb_desc, rb_func = rollback_plan
                                logger.warning(
                                    "Attempting rollback for modification [%d]: %s",
                                    i,
                                    rb_desc,
                                )
                                if self.event_emitter is not None:
                                    _rp = self._mod_payload(mod, i)
                                    _rp["description"] = rb_desc
                                    self._emit(DeferredEvent.DEFERRED_ROLLBACK_STARTED, _rp)
                                _rb_succeeded = False
                                try:
                                    if rb_func():
                                        safe_verify(
                                            self.mba,
                                            (
                                                "after rollback of deferred "
                                                f"modification [{i}] {mod.description}"
                                            ),
                                            logger_func=logger.error,
                                            capture_blocks=capture_blocks,
                                            capture_metadata={
                                                "phase": "rollback_verify",
                                                "rolled_back_modification": current_mod_trace,
                                                "recent_modifications": list(
                                                    recent_modifications
                                                ),
                                            },
                                        )
                                        rolled_back_ok = True
                                        _rb_succeeded = True
                                except RuntimeError:
                                    rolled_back_ok = False
                                except Exception as rb_exc:
                                    logger.error(
                                        "Rollback raised exception for modification [%d]: %s",
                                        i,
                                        rb_exc,
                                        exc_info=True,
                                    )
                                    rolled_back_ok = False
                                if self.event_emitter is not None:
                                    _rfp = self._mod_payload(mod, i)
                                    _rfp["result"] = "rolled_back" if _rb_succeeded else "failed"
                                    self._emit(DeferredEvent.DEFERRED_ROLLBACK_FINISHED, _rfp)

                            if rolled_back_ok:
                                rolled_back += 1
                                logger.warning(
                                    "    RESULT: ROLLED BACK (modification skipped)"
                                )
                                if continue_on_verify_failure:
                                    logger.warning(
                                        "Continuing after rolled-back deferred "
                                        "modification [%d]",
                                        i,
                                    )
                                    continue

                            self.verify_failed = True
                            logger.warning(
                                "Aborting deferred apply after verify failure at "
                                "modification [%d]",
                                i,
                            )
                            break

                    successful += 1
                    logger.info("    RESULT: SUCCESS")
                    if self.event_emitter is not None:
                        _p = self._mod_payload(mod, i)
                        _p["result"] = "success"
                        self._emit(DeferredEvent.DEFERRED_MOD_APPLIED, _p)
                else:
                    failed += 1
                    logger.warning("    RESULT: FAILED")
                    if self.event_emitter is not None:
                        _p = self._mod_payload(mod, i)
                        _p["result"] = "failed"
                        self._emit(DeferredEvent.DEFERRED_MOD_FAILED, _p)
                    # Edge-split precondition failures are safe rejections
                    # (block opcode changed between analysis and apply time).
                    # Skip the failed edit and continue with remaining mods
                    # instead of aborting the entire batch.
                    if mod.mod_type == ModificationType.EDGE_REDIRECT_VIA_PRED_SPLIT:
                        logger.warning(
                            "Skipping failed edge-split [%d] and continuing "
                            "(safe precondition rejection, not MBA corruption): %s",
                            i, mod.description,
                        )
                        continue
                    logger.warning(
                        "Aborting deferred apply after first failed modification "
                        "to avoid compounding CFG corruption"
                    )
                    break
            except Exception as e:
                failed += 1
                logger.error("    RESULT: EXCEPTION: %s", e)
                if self.event_emitter is not None:
                    _ep = self._mod_payload(mod, i)
                    _ep["result"] = "failed"
                    _ep["error"] = str(e)
                    self._emit(DeferredEvent.DEFERRED_MOD_FAILED, _ep)
                import traceback
                logger.error("    TRACEBACK: %s", traceback.format_exc())
                capture_failure_artifact(
                    self.mba,
                    f"exception during deferred modification [{i}] {mod.description}",
                    e,
                    logger_func=logger.error,
                    capture_blocks=_collect_capture_blocks(
                        source_before_snapshot,
                        target_before_snapshot,
                    ),
                    capture_metadata={
                        "phase": "apply_exception",
                        "modification": {
                            "index": i,
                            "description": mod.description,
                            "mod_type": mod.mod_type.name,
                            "priority": mod.priority,
                            "rule_priority": mod.rule_priority,
                            "block_serial": mod.block_serial,
                            "new_target": mod.new_target,
                            "before": source_before_snapshot,
                            "target_before": target_before_snapshot,
                        },
                        "recent_modifications": list(recent_modifications),
                    },
                )
                logger.warning(
                    "Aborting deferred apply after exception in modification"
                )
                break

        logger.info(
            "Applied %d/%d modifications (%d failed, %d rolled back)",
            successful, total_mod_count, failed, rolled_back
        )

        # Mark chains dirty and run optimizations
        if successful > 0:
            self.mba.mark_chains_dirty()

        def _finish(result_count: int) -> int:
            """Shared exit: emit APPLY_FINISHED and mark applied."""
            self._applied = True
            if self.event_emitter is not None:
                _fp = self._base_payload()
                _fp.update({
                    "applied": result_count,
                    "failed": failed,
                    "rolled_back": rolled_back,
                    "verify_failed": self.verify_failed,
                })
                self._emit(DeferredEvent.DEFERRED_APPLY_FINISHED, _fp)
            return result_count

        if self.verify_failed:
            logger.warning(
                "Skipping post-apply cleanup because incremental verify has "
                "already failed; caller must treat MBA as suspect"
            )
            return _finish(successful)

        if successful > 0:
            if post_apply_hook is not None:
                try:
                    post_apply_hook()
                except Exception as e:
                    self.verify_failed = True
                    contract_violations = getattr(e, "violations", None)
                    contract_summary = getattr(e, "summary", None)
                    if contract_violations:
                        logger.error(
                            "post_apply_hook raised cfg contract failure: %s",
                            contract_summary or e,
                            exc_info=True,
                        )
                    else:
                        logger.error("post_apply_hook raised: %s", e, exc_info=True)
                    capture_failure_artifact(
                        self.mba,
                        "exception during deferred post-apply hook",
                        e,
                        logger_func=logger.error,
                        capture_metadata={
                            "phase": (
                                "post_apply_contract_failure"
                                if contract_violations
                                else "post_apply_hook_exception"
                            ),
                            "applied_modifications": successful,
                            "queued_modifications": len(sorted_mods),
                            "recent_modifications": list(recent_modifications),
                            "contract_violations": (
                                [
                                    {
                                        "code": getattr(v, "code", None),
                                        "block_serial": getattr(v, "block_serial", None),
                                        "message": getattr(v, "message", None),
                                    }
                                    for v in contract_violations
                                ]
                                if contract_violations
                                else None
                            ),
                        },
                    )

                    if enable_snapshot_rollback and self._pre_snapshot is not None:
                        logger.warning(
                            "Attempting snapshot rollback after post_apply_hook failure "
                            "(nblocks=%d)",
                            self._pre_snapshot.num_blocks,
                        )
                        if self._restore_from_snapshot(self._pre_snapshot):
                            self.verify_failed = False
                            logger.warning(
                                "Successfully restored MBA from snapshot after "
                                "post_apply_hook failure"
                            )
                            return _finish(0)
                        logger.error("Snapshot rollback failed after post_apply_hook failure")

                    return _finish(successful)

            if defer_post_apply_maintenance:
                return _finish(successful)

            if run_deep_cleaning:
                mba_deep_cleaning(self.mba, call_mba_combine_block=True)
            elif run_optimize_local:
                self.mba.optimize_local(0)
            else:
                # Caller requested no optimize_local. Still run conservative
                # cleanup so deferred CFG rewrites don't leave transient orphans.
                mba_deep_cleaning(self.mba, call_mba_combine_block=False)

            try:
                safe_verify(
                    self.mba,
                    "after deferred modifications",
                    logger_func=logger.error,
                    capture_metadata={
                        "phase": "post_apply_verify",
                        "applied_modifications": successful,
                        "queued_modifications": len(sorted_mods),
                        "recent_modifications": list(recent_modifications),
                    },
                )
            except RuntimeError:
                # The modifications are already applied in-place and cannot
                # be rolled back.  Setting verify_failed lets callers know
                # the MBA is in a suspect state so they can stop further
                # processing instead of letting IDA continue with a
                # corrupted MBA (which causes hangs at later maturity levels).
                self.verify_failed = True
                logger.warning(
                    "MBA verify failed after applying %d deferred modifications "
                    "-- marking verify_failed so callers can abort gracefully",
                    successful,
                )
                if self.event_emitter is not None:
                    _vfp = self._base_payload()
                    _vfp["result"] = "verify_failed"
                    _vfp["error"] = "post-apply verify failed"
                    self._emit(DeferredEvent.DEFERRED_VERIFY_FAILED, _vfp)

                # If snapshot rollback is enabled and we have a snapshot, try full restoration
                if enable_snapshot_rollback and self._pre_snapshot is not None:
                    logger.warning(
                        "Attempting snapshot-based rollback (nblocks=%d)",
                        self._pre_snapshot.num_blocks,
                    )
                    if self._restore_from_snapshot(self._pre_snapshot):
                        self.verify_failed = False
                        logger.warning(
                            "Successfully restored MBA from snapshot after verify failure"
                        )
                        # Return 0 to indicate no successful changes (rolled back)
                        return _finish(0)
                    else:
                        logger.error("Snapshot rollback failed, MBA remains corrupted")

                # Best-effort recovery: conservative cleanup + one re-verify
                # attempt. If this succeeds, callers can safely continue.
                try:
                    mba_deep_cleaning(self.mba, call_mba_combine_block=False)
                    safe_verify(
                        self.mba,
                        "after deferred modifications (recovery)",
                        logger_func=logger.error,
                        capture_metadata={
                            "phase": "post_apply_recovery_verify",
                            "applied_modifications": successful,
                            "queued_modifications": len(sorted_mods),
                            "recent_modifications": list(recent_modifications),
                        },
                    )
                    self.verify_failed = False
                    logger.warning(
                        "Recovered MBA after deferred-apply verify failure via "
                        "conservative cleanup"
                    )
                except RuntimeError:
                    pass

        return _finish(successful)

    def _prepare_rollback(self, mod: GraphModification) -> tuple[str, callable] | None:
        """Prepare a best-effort rollback closure for reversible modifications.

        Rollback support is intentionally limited to edge-rewrite operations that
        can be restored with existing CFG helpers without introducing new blocks.
        """
        blk = self.mba.get_mblock(mod.block_serial)
        if blk is None:
            return None

        if mod.mod_type == ModificationType.BLOCK_GOTO_CHANGE:
            if blk.nsucc() != 1:
                return None
            old_target = blk.succset[0]
            block_serial = blk.serial

            def _rollback_goto() -> bool:
                cur_blk = self.mba.get_mblock(block_serial)
                if cur_blk is None:
                    return False
                return change_1way_block_successor(cur_blk, old_target, verify=False)

            return (f"restore goto {block_serial} -> {old_target}", _rollback_goto)

        if mod.mod_type == ModificationType.BLOCK_TARGET_CHANGE:
            if blk.tail is None or not hasattr(blk.tail, "d"):
                return None
            old_target = blk.tail.d.b
            block_serial = blk.serial

            def _rollback_target() -> bool:
                cur_blk = self.mba.get_mblock(block_serial)
                if cur_blk is None:
                    return False
                return change_2way_block_conditional_successor(
                    cur_blk, old_target, verify=False
                )

            return (
                f"restore conditional target {block_serial} -> {old_target}",
                _rollback_target,
            )

        if mod.mod_type == ModificationType.EDGE_REDIRECT_VIA_PRED_SPLIT:
            # Best-effort: rewire via_pred back to src_block.
            # No trampoline block to clean up — just undo the direct redirect.
            src_block = mod.src_block
            via_pred = mod.via_pred
            if src_block is None or via_pred is None:
                return None

            def _rollback_edge_redirect() -> bool:
                pred_blk = self.mba.get_mblock(via_pred)
                src_blk = self.mba.get_mblock(src_block)
                if pred_blk is None or src_blk is None:
                    return False
                logger.warning(
                    "edge_redirect_via_pred_split rollback: rewiring pred=%d "
                    "back to src=%d",
                    via_pred, src_block,
                )
                if not change_1way_block_successor(pred_blk, src_block, verify=False):
                    logger.error(
                        "edge_redirect_via_pred_split rollback failed: "
                        "could not rewire pred=%d -> src=%d",
                        via_pred, src_block,
                    )
                    return False
                self.mba.mark_chains_dirty()
                return True

            return (
                f"rollback edge_redirect pred={via_pred} -> src={src_block}",
                _rollback_edge_redirect,
            )

        if mod.mod_type == ModificationType.EDGE_SPLIT_TRAMPOLINE:
            src_block = mod.src_block
            via_pred = mod.via_pred
            if src_block is None or via_pred is None:
                return None

            def _rollback_edge_split_trampoline() -> bool:
                pred_blk = self.mba.get_mblock(via_pred)
                src_blk = self.mba.get_mblock(src_block)
                if pred_blk is None or src_blk is None:
                    return False
                logger.warning(
                    "edge_split_trampoline rollback: rewiring pred=%d back to src=%d",
                    via_pred, src_block,
                )
                if not change_1way_block_successor(pred_blk, src_block, verify=False):
                    logger.error(
                        "edge_split_trampoline rollback failed: could not rewire pred=%d -> src=%d",
                        via_pred, src_block,
                    )
                    return False
                self.mba.mark_chains_dirty()
                return True

            return (
                f"rollback edge_split_trampoline pred={via_pred} -> src={src_block}",
                _rollback_edge_split_trampoline,
            )

        return None

    def _apply_single(self, mod: GraphModification) -> bool:
        """Apply a single modification. Returns True on success."""
        blk = self.mba.get_mblock(mod.block_serial)
        if blk is None:
            logger.warning("Block %d not found", mod.block_serial)
            return False

        if mod.mod_type == ModificationType.BLOCK_GOTO_CHANGE:
            return self._apply_goto_change(blk, mod.new_target)

        elif mod.mod_type == ModificationType.BLOCK_TARGET_CHANGE:
            return self._apply_target_change(blk, mod.new_target)

        elif mod.mod_type == ModificationType.BLOCK_CONVERT_TO_GOTO:
            return self._apply_convert_to_goto(blk, mod.new_target)

        elif mod.mod_type == ModificationType.INSN_REMOVE:
            return self._apply_insn_remove(blk, mod.insn_ea)

        elif mod.mod_type == ModificationType.INSN_NOP:
            return self._apply_insn_nop(blk, mod.insn_ea)

        elif mod.mod_type == ModificationType.BLOCK_CREATE_WITH_REDIRECT:
            return self._apply_create_and_redirect(
                blk,
                mod.final_target,
                mod.instructions_to_copy,
                mod.is_0_way,
                expected_serial=mod.expected_serial,
            )

        elif mod.mod_type == ModificationType.BLOCK_CREATE_WITH_CONDITIONAL_REDIRECT:
            return self._apply_create_conditional_redirect(
                blk,
                mod.new_target,
                mod.conditional_target,
                mod.fallthrough_target,
                expected_conditional_serial=mod.expected_conditional_serial,
                expected_fallthrough_serial=mod.expected_fallthrough_serial,
            )

        elif mod.mod_type == ModificationType.BLOCK_DUPLICATE_AND_REDIRECT:
            return self._apply_duplicate_block_and_redirect(
                source_blk=blk,
                pred_serial=mod.via_pred,
                target_serial=mod.new_target,
                expected_serial=mod.expected_serial,
                expected_secondary_serial=mod.expected_secondary_serial,
            )

        elif mod.mod_type == ModificationType.EDGE_REDIRECT_VIA_PRED_SPLIT:
            return self._apply_edge_redirect_via_pred_split(
                blk, mod.old_target, mod.new_target, mod.via_pred, mod.clone_until
            )

        elif mod.mod_type == ModificationType.EDGE_SPLIT_TRAMPOLINE:
            return self._apply_edge_split_trampoline(
                source_block_serial=mod.src_block,
                via_pred=mod.via_pred,
                old_target=mod.old_target,
                new_target=mod.new_target,
                expected_serial=mod.expected_serial,
            )

        elif mod.mod_type == ModificationType.EDGE_REMOVE:
            return self._apply_remove_edge(blk, mod.new_target)

        elif mod.mod_type == ModificationType.PRIVATE_TERMINAL_SUFFIX:
            return self._apply_private_terminal_suffix(
                anchor_blk=blk,
                shared_entry_serial=mod.new_target,
                suffix_serials=mod.suffix_serials or (),
                clone_expected_serials=mod.clone_expected_serials or (),
            )

        elif mod.mod_type == ModificationType.PRIVATE_TERMINAL_SUFFIX_GROUP:
            return self._apply_private_terminal_suffix_group(
                anchors=mod.anchors or (),
                shared_entry_serial=mod.new_target,
                suffix_serials=mod.suffix_serials or (),
                per_anchor_clone_expected_serials=mod.per_anchor_clone_expected_serials or (),
            )

        elif mod.mod_type == ModificationType.DIRECT_TERMINAL_LOWERING_GROUP:
            return self._apply_direct_terminal_lowering_group(mba, mod)

        else:
            logger.warning("Unknown modification type: %s", mod.mod_type)
            return False

    def _apply_goto_change(self, blk: ida_hexrays.mblock_t, new_target: int) -> bool:
        """Redirect a 1-way block successor (tail may be non-goto)."""
        if blk.nsucc() != 1:
            logger.warning(
                "Block %d is not 1-way (nsucc=%d)",
                blk.serial,
                blk.nsucc(),
            )
            return False

        return change_1way_block_successor(blk, new_target, verify=False)

    def _apply_target_change(self, blk: ida_hexrays.mblock_t, new_target: int) -> bool:
        """Change a conditional jump's target."""
        if blk.tail is None:
            return False

        # Check if it's a conditional jump
        if blk.tail.opcode not in [
            ida_hexrays.m_jnz, ida_hexrays.m_jz,
            ida_hexrays.m_jae, ida_hexrays.m_jb,
            ida_hexrays.m_ja, ida_hexrays.m_jbe,
            ida_hexrays.m_jg, ida_hexrays.m_jge,
            ida_hexrays.m_jl, ida_hexrays.m_jle,
        ]:
            logger.warning(
                "Block %d doesn't end with conditional jump",
                blk.serial
            )
            return False

        return change_2way_block_conditional_successor(blk, new_target, verify=False)

    def _apply_convert_to_goto(self, blk: ida_hexrays.mblock_t, goto_target: int) -> bool:
        """Convert a 2-way block to a 1-way goto."""
        return make_2way_block_goto(blk, goto_target, verify=False)

    def _apply_remove_edge(self, blk: ida_hexrays.mblock_t, to_serial: int) -> bool:
        """Remove a single outgoing edge from *blk* to *to_serial*."""
        return remove_block_edge(blk, to_serial, verify=False)

    def _apply_insn_remove(self, blk: ida_hexrays.mblock_t, insn_ea: int) -> bool:
        """Remove an instruction by its EA."""
        insn = blk.head
        while insn:
            if insn.ea == insn_ea:
                blk.remove_from_block(insn)
                return True
            insn = insn.next

        logger.warning(
            "Instruction at EA %s not found in block %d",
            hex(insn_ea), blk.serial
        )
        return False

    def _apply_insn_nop(self, blk: ida_hexrays.mblock_t, insn_ea: int) -> bool:
        """NOP an instruction by its EA."""
        insn = blk.head
        while insn:
            if insn.ea == insn_ea:
                blk.make_nop(insn)
                return True
            insn = insn.next

        logger.warning(
            "Instruction at EA %s not found in block %d",
            hex(insn_ea), blk.serial
        )
        return False

    def _apply_create_and_redirect(
        self,
        source_blk: ida_hexrays.mblock_t,
        final_target: int,
        instructions_to_copy: list | tuple | None,
        is_0_way: bool,
        expected_serial: int | None,
    ) -> bool:
        """
        Create a standalone intermediate block and redirect source through it.

        Creates: source_blk -> new_block -> final_target

        Uses :func:`create_standalone_block` instead of :func:`create_block`
        to avoid corrupting ``ref_block``'s CFG edges (INTERR 50856/50858).
        """
        if instructions_to_copy is None:
            instructions_to_copy = []
        instructions_to_copy = _prepare_block_creation_instructions(
            self.mba,
            instructions_to_copy,
        )

        # Precondition: this helper rewires a single outgoing edge. If the
        # source is not 1-way, creating the new block first can leave orphans
        # when the final redirect fails.
        if source_blk.nsucc() != 1:
            logger.warning(
                "create_and_redirect requires 1-way source block; block %d has nsucc=%d",
                source_blk.serial,
                source_blk.nsucc(),
            )
            return False
        if source_blk.serial == 0:
            logger.warning(
                "create_and_redirect requires non-entry source block; block %d is entry",
                source_blk.serial,
            )
            return False

        mba = self.mba

        # Find reference block for copy_block template (tail block, avoiding XTRN/STOP)
        tail_serial = mba.qty - 1
        ref_block = mba.get_mblock(tail_serial)
        while ref_block.type in (ida_hexrays.BLT_XTRN, ida_hexrays.BLT_STOP):
            tail_serial -= 1
            ref_block = mba.get_mblock(tail_serial)

        # Get target block to check if it's 0-way
        target_blk = mba.get_mblock(final_target)
        actual_is_0_way = is_0_way or (target_blk and target_blk.type == ida_hexrays.BLT_0WAY)

        try:
            old_stop_serial = mba.qty - 1
            old_stop_pred_serials = [
                serial
                for serial in range(mba.qty)
                if (blk := mba.get_mblock(serial)) is not None
                and blk.nsucc() == 1
                and blk.succ(0) == old_stop_serial
            ]
            # Create a standalone block -- ref_block's CFG edges are NOT modified.
            new_block = create_standalone_block(
                ref_block,
                instructions_to_copy,
                target_serial=None if actual_is_0_way else final_target,
                is_0_way=actual_is_0_way,
                verify=False,
            )
            if expected_serial is not None and new_block.serial != expected_serial:
                logger.warning(
                    "create_and_redirect: created blk[%d], expected blk[%d]",
                    new_block.serial,
                    expected_serial,
                )
                return False
            new_stop_serial = mba.qty - 1
            for pred_serial in old_stop_pred_serials:
                pred_blk = mba.get_mblock(pred_serial)
                if pred_blk is None or pred_blk.serial == new_block.serial:
                    continue
                if pred_blk.nsucc() != 1 or pred_blk.succ(0) != new_block.serial:
                    continue
                if not change_1way_block_successor(pred_blk, new_stop_serial, verify=False):
                    logger.warning(
                        "create_and_redirect: failed to relocate stop predecessor blk[%d] -> blk[%d]",
                        pred_blk.serial,
                        new_stop_serial,
                    )
                    return False

            # Ensure all instructions in the new block have safe EAs within
            # the function range to prevent INTERR 50863.
            safe_ea = mba.entry_ea
            cur = new_block.head
            while cur is not None:
                cur.ea = safe_ea
                cur = cur.next

            # Redirect source block to the new block
            if not change_1way_block_successor(source_blk, new_block.serial, verify=False):
                logger.warning(
                    "Failed to redirect block %d to new block %d",
                    source_blk.serial, new_block.serial
                )
                # Best-effort cleanup for the partially-created orphan block.
                try:
                    mba_deep_cleaning(self.mba, call_mba_combine_block=False)
                except Exception:
                    pass
                return False

            logger.debug(
                "Created block %d: %d -> %d -> %d",
                new_block.serial, source_blk.serial, new_block.serial, final_target
            )
            return True

        except Exception as e:
            logger.error(
                "Exception in create_and_redirect for block %d: %s",
                source_blk.serial, e
            )
            return False

    def _apply_create_conditional_redirect(
        self,
        source_blk: ida_hexrays.mblock_t,
        ref_blk_serial: int,
        conditional_target_serial: int,
        fallthrough_target_serial: int,
        *,
        expected_conditional_serial: int | None = None,
        expected_fallthrough_serial: int | None = None,
    ) -> bool:
        """
        Create a conditional 2-way block with two wired successors.

        Uses the proven pattern from fix_pred_cond_jump_block.py:
        1. Duplicate the reference conditional block (preserving tail instruction)
        2. Create a NOP-goto block as the fallthrough successor (IDA requires
           physical adjacency for BLT_2WAY fallthrough)
        3. Wire the conditional target directly
        4. Redirect source block to the new conditional block

        Creates:
            source_blk -> new_conditional_blk -> conditional_target (jcc taken)
                                                -> nop_blk -> fallthrough_target

        Args:
            source_blk: Block whose successor will be changed to the new block
            ref_blk_serial: Reference block to duplicate (should be conditional)
            conditional_target_serial: Target for conditional jump (jcc taken)
            fallthrough_target_serial: Target for fallthrough (via NOP-goto)

        Returns:
            True on success, False on failure
        """
        mba = self.mba

        if source_blk.nsucc() != 1:
            logger.warning(
                "create_conditional_redirect requires 1-way source block; block %d has nsucc=%d",
                source_blk.serial,
                source_blk.nsucc(),
            )
            return False

        # Get reference block to duplicate
        ref_blk = mba.get_mblock(ref_blk_serial)
        if ref_blk is None:
            logger.warning(
                "Reference block %d not found for conditional redirect",
                ref_blk_serial
            )
            return False

        # Verify reference block is conditional
        if ref_blk.tail is None or not ida_hexrays.is_mcode_jcond(ref_blk.tail.opcode):
            logger.warning(
                "Reference block %d is not conditional (opcode=%s)",
                ref_blk_serial,
                ref_blk.tail.opcode if ref_blk.tail else "none"
            )
            return False

        try:
            # Step 1: Duplicate the conditional block
            # This creates a copy with the same instructions including the
            # conditional tail instruction.
            # For conditional blocks, duplicate_block also creates a NOP
            # fallthrough block automatically (nop_blk).
            new_cond_blk, nop_blk = duplicate_block(ref_blk, verify=False)

            if nop_blk is None:
                logger.warning(
                    "duplicate_block did not create NOP fallthrough for block %d",
                    new_cond_blk.serial
                )
                return False
            if (
                expected_conditional_serial is not None
                and new_cond_blk.serial != expected_conditional_serial
            ):
                logger.warning(
                    "create_conditional_redirect: created conditional blk[%d], expected blk[%d]",
                    new_cond_blk.serial,
                    expected_conditional_serial,
                )
                return False
            if (
                expected_fallthrough_serial is not None
                and nop_blk.serial != expected_fallthrough_serial
            ):
                logger.warning(
                    "create_conditional_redirect: created fallthrough blk[%d], expected blk[%d]",
                    nop_blk.serial,
                    expected_fallthrough_serial,
                )
                return False

            logger.debug(
                "Duplicated conditional block %d -> %d (with NOP fallthrough %d)",
                ref_blk_serial, new_cond_blk.serial, nop_blk.serial
            )

            # Step 2: Wire the conditional target (jcc taken branch)
            # Change the conditional jump's target operand to point to the
            # desired conditional_target_serial
            if not change_2way_block_conditional_successor(
                new_cond_blk, conditional_target_serial, verify=False
            ):
                logger.warning(
                    "Failed to wire conditional target %d -> %d",
                    new_cond_blk.serial, conditional_target_serial
                )
                return False

            logger.debug(
                "Wired conditional target: %d -> %d (jcc taken)",
                new_cond_blk.serial, conditional_target_serial
            )

            # Step 3: Wire the NOP-goto block to the fallthrough target
            # The NOP block was already created by duplicate_block and is
            # adjacent to new_cond_blk (satisfies BLT_2WAY fallthrough requirement).
            # Now we just redirect its goto to the actual fallthrough_target_serial.
            if not change_1way_block_successor(nop_blk, fallthrough_target_serial, verify=False):
                logger.warning(
                    "Failed to wire NOP fallthrough %d -> %d",
                    nop_blk.serial, fallthrough_target_serial
                )
                return False

            logger.debug(
                "Wired NOP fallthrough: %d -> %d",
                nop_blk.serial, fallthrough_target_serial
            )

            # Step 4: Redirect source block to the new conditional block
            if not change_1way_block_successor(source_blk, new_cond_blk.serial, verify=False):
                logger.warning(
                    "Failed to redirect source %d -> new conditional %d",
                    source_blk.serial, new_cond_blk.serial
                )
                try:
                    mba_deep_cleaning(self.mba, call_mba_combine_block=False)
                except Exception:
                    pass
                return False

            logger.debug(
                "Created conditional redirect: %d -> %d (cond) -> jcc:%d / ft:%d (via NOP %d)",
                source_blk.serial, new_cond_blk.serial,
                conditional_target_serial, fallthrough_target_serial, nop_blk.serial
            )

            return True

        except Exception as e:
            logger.error(
                "Exception in create_conditional_redirect for block %d: %s",
                source_blk.serial, e
            )
            import traceback
            logger.error("Traceback: %s", traceback.format_exc())
            return False

    def _apply_duplicate_block_and_redirect(
        self,
        *,
        source_blk: ida_hexrays.mblock_t,
        pred_serial: int | None,
        target_serial: int | None,
        expected_serial: int | None,
        expected_secondary_serial: int | None,
    ) -> bool:
        """Duplicate ``source_blk`` and redirect ``pred_serial`` to the clone."""
        if not self._check_duplicate_block_preconditions(
            source_block_serial=source_blk.serial,
            pred_serial=pred_serial,
            target_serial=target_serial,
        ):
            return False

        if pred_serial is None:
            return False

        pred_blk = self.mba.get_mblock(pred_serial)
        if pred_blk is None:
            logger.warning(
                "duplicate_block: predecessor blk[%d] missing at apply-time",
                pred_serial,
            )
            return False

        try:
            old_stop_serial = self.mba.qty - 1
            old_stop_pred_serials = [
                serial
                for serial in range(self.mba.qty)
                if (blk := self.mba.get_mblock(serial)) is not None
                and blk.nsucc() == 1
                and blk.succ(0) == old_stop_serial
            ]

            if source_blk.nsucc() == 2:
                conditional_target = source_blk.tail.d.b
                fallthrough_target = next(
                    (source_blk.succ(i) for i in range(source_blk.nsucc()) if source_blk.succ(i) != conditional_target),
                    None,
                )
                if fallthrough_target is None:
                    logger.warning(
                        "duplicate_block: src blk[%d] missing fallthrough successor",
                        source_blk.serial,
                    )
                    return False

                duplicated_blk = self.mba.copy_block(source_blk, self.mba.qty - 1)

                prev_pred_serials = [x for x in duplicated_blk.predset]
                for prev_serial in prev_pred_serials:
                    duplicated_blk.predset._del(prev_serial)

                prev_blk = duplicated_blk.prevb
                if prev_blk is not None and prev_blk.serial != source_blk.serial:
                    tail = prev_blk.tail
                    has_explicit_target = (
                        tail is not None
                        and (
                            tail.opcode == ida_hexrays.m_goto
                            or ida_hexrays.is_mcode_jcond(tail.opcode)
                            or tail.opcode == ida_hexrays.m_ijmp
                        )
                    )
                    if not has_explicit_target and prev_blk.nsucc() == 1:
                        if tail is not None and tail.opcode == ida_hexrays.m_ret:
                            logger.debug(
                                "duplicate_block: skipping m_ret fall-through fix for blk[%d]",
                                prev_blk.serial,
                            )
                        else:
                            original_target = prev_blk.succset[0]
                            exit_serial = self.mba.qty - 1
                            if original_target == duplicated_blk.serial:
                                original_target = exit_serial
                            insert_goto_instruction(
                                prev_blk,
                                original_target,
                                nop_previous_instruction=False,
                            )
                            prev_blk.succset._del(duplicated_blk.serial)
                            if original_target not in [
                                prev_blk.succset[i] for i in range(prev_blk.succset.size())
                            ]:
                                prev_blk.succset.push_back(original_target)
                            prev_blk.type = ida_hexrays.BLT_1WAY
                            prev_blk.flags |= ida_hexrays.MBL_GOTO
                            prev_blk.mark_lists_dirty()

                duplicated_default = create_standalone_block(
                    source_blk,
                    [],
                    target_serial=fallthrough_target,
                    is_0_way=False,
                    verify=False,
                )
                duplicated_blk.flags &= ~ida_hexrays.MBL_GOTO
                if not _rewire_edge(
                    duplicated_blk,
                    [x for x in duplicated_blk.succset],
                    [duplicated_default.serial, conditional_target],
                    new_block_type=ida_hexrays.BLT_2WAY,
                    verify=False,
                ):
                    return False
                duplicated_blk.tail.d = ida_hexrays.mop_t()
                duplicated_blk.tail.d.make_blkref(conditional_target)
                duplicated_blk.mark_lists_dirty()
                self.mba.mark_chains_dirty()
            else:
                final_target = target_serial
                if final_target is None and source_blk.nsucc() == 1:
                    final_target = source_blk.succ(0)

                instructions_to_copy = []
                cur_ins = source_blk.head
                while cur_ins is not None:
                    if (
                        source_blk.nsucc() == 1
                        and source_blk.tail is not None
                        and source_blk.tail.opcode == ida_hexrays.m_goto
                        and cur_ins.next is None
                    ):
                        break
                    cloned_ins = ida_hexrays.minsn_t(cur_ins)
                    cloned_ins.setaddr(self.mba.entry_ea)
                    instructions_to_copy.append(cloned_ins)
                    cur_ins = cur_ins.next

                duplicated_blk = create_standalone_block(
                    source_blk,
                    instructions_to_copy,
                    target_serial=final_target,
                    is_0_way=final_target is None,
                    verify=False,
                )
                duplicated_default = None
            new_stop_serial = self.mba.qty - 1
            transient_stop_targets = {duplicated_blk.serial}
            if duplicated_default is not None:
                transient_stop_targets.add(duplicated_default.serial)
            for stop_pred_serial in old_stop_pred_serials:
                stop_pred_blk = self.mba.get_mblock(stop_pred_serial)
                if stop_pred_blk is None or stop_pred_blk.serial == duplicated_blk.serial:
                    continue
                if (
                    stop_pred_blk.nsucc() != 1
                    or stop_pred_blk.succ(0) not in transient_stop_targets
                ):
                    continue
                if not change_1way_block_successor(
                    stop_pred_blk,
                    new_stop_serial,
                    verify=False,
                ):
                    logger.warning(
                        "duplicate_block: failed to relocate stop predecessor blk[%d] -> blk[%d]",
                        stop_pred_blk.serial,
                        new_stop_serial,
                    )
                    return False

            if expected_serial is not None and duplicated_blk.serial != expected_serial:
                logger.warning(
                    "duplicate_block: created clone blk[%d], expected blk[%d]",
                    duplicated_blk.serial,
                    expected_serial,
                )
                return False
            if expected_secondary_serial is not None:
                if duplicated_default is None:
                    logger.warning(
                        "duplicate_block: missing duplicated fallthrough blk for blk[%d], expected blk[%d]",
                        source_blk.serial,
                        expected_secondary_serial,
                    )
                    return False
                if duplicated_default.serial != expected_secondary_serial:
                    logger.warning(
                        "duplicate_block: created fallthrough blk[%d], expected blk[%d]",
                        duplicated_default.serial,
                        expected_secondary_serial,
                    )
                    return False

            if pred_blk.nsucc() == 1:
                if not change_1way_block_successor(
                    pred_blk,
                    duplicated_blk.serial,
                    verify=False,
                ):
                    return False
            elif (
                pred_blk.nsucc() == 2
                and pred_blk.tail is not None
                and ida_hexrays.is_mcode_jcond(pred_blk.tail.opcode)
                and pred_blk.tail.d.t == ida_hexrays.mop_b
                and pred_blk.tail.d.b == source_blk.serial
            ):
                if not change_2way_block_conditional_successor(
                    pred_blk,
                    duplicated_blk.serial,
                    verify=False,
                ):
                    return False
            else:
                logger.warning(
                    "duplicate_block: predecessor blk[%d] cannot redirect to clone blk[%d]",
                    pred_blk.serial,
                    duplicated_blk.serial,
                )
                return False

            logger.debug(
                "duplicate_block: pred=%d -> clone=%d (source=%d target=%s secondary=%s)",
                pred_blk.serial,
                duplicated_blk.serial,
                source_blk.serial,
                target_serial,
                duplicated_default.serial if duplicated_default is not None else None,
            )
            return True

        except Exception as exc:
            logger.error(
                "Exception in duplicate_block for src=%d pred=%s target=%s: %s",
                source_blk.serial,
                pred_serial,
                target_serial,
                exc,
            )
            import traceback
            logger.error("Traceback: %s", traceback.format_exc())
            return False

    def _apply_private_terminal_suffix(
        self,
        *,
        anchor_blk: ida_hexrays.mblock_t,
        shared_entry_serial: int,
        suffix_serials: tuple[int, ...],
        clone_expected_serials: tuple[int, ...],
    ) -> bool:
        """Clone shared suffix chain and redirect anchor to the clone.

        The suffix is cloned backward (tail first) because ``copy_block``
        inserts before the STOP block. After all clones are created, the
        chain is wired and the anchor is redirected.

        Fail-closed on:
        - anchor not 1-way
        - any suffix block not found
        - suffix interior blocks not 1-way
        - suffix final block not 0-way (nsucc != 0)
        - expected serial mismatch
        """
        mba = self.mba
        if mba is None:
            return False

        # Pre-check: anchor must be 1-way
        if anchor_blk.nsucc() != 1:
            logger.warning(
                "private_terminal_suffix: anchor blk[%d] is not 1-way (nsucc=%d)",
                anchor_blk.serial,
                anchor_blk.nsucc(),
            )
            return False

        # Verify anchor still targets the shared entry
        current_succ = anchor_blk.succ(0)
        if current_succ != shared_entry_serial:
            logger.warning(
                "private_terminal_suffix: anchor blk[%d] targets blk[%d], "
                "expected shared_entry blk[%d] — fail closed",
                anchor_blk.serial,
                current_succ,
                shared_entry_serial,
            )
            return False

        if not suffix_serials:
            logger.warning("private_terminal_suffix: empty suffix_serials")
            return False

        # Validate suffix topology
        for idx, suffix_serial in enumerate(suffix_serials):
            suffix_blk = mba.get_mblock(suffix_serial)
            if suffix_blk is None:
                logger.warning(
                    "private_terminal_suffix: suffix blk[%d] not found",
                    suffix_serial,
                )
                return False
            if idx < len(suffix_serials) - 1:
                if suffix_blk.nsucc() != 1:
                    logger.warning(
                        "private_terminal_suffix: interior suffix blk[%d] is not 1-way (nsucc=%d)",
                        suffix_serial,
                        suffix_blk.nsucc(),
                    )
                    return False
            else:
                if suffix_blk.nsucc() != 0:
                    logger.warning(
                        "private_terminal_suffix: final suffix blk[%d] is not 0-way (nsucc=%d)",
                        suffix_serial,
                        suffix_blk.nsucc(),
                    )
                    return False

        try:
            old_stop_serial = mba.qty - 1
            old_stop_pred_serials = [
                serial
                for serial in range(mba.qty)
                if (blk := mba.get_mblock(serial)) is not None
                and blk.nsucc() == 1
                and blk.succ(0) == old_stop_serial
            ]

            cloned_serials: list[int] = []
            # Clone suffix blocks in forward order (each creates a new block)
            for idx, suffix_serial in enumerate(suffix_serials):
                template_blk = mba.get_mblock(suffix_serial)
                if template_blk is None:
                    return False

                is_last = idx == len(suffix_serials) - 1

                # Collect instructions from template (skip trailing goto for non-final)
                instructions_to_copy = []
                cur_ins = template_blk.head
                while cur_ins is not None:
                    if (
                        not is_last
                        and template_blk.nsucc() == 1
                        and template_blk.tail is not None
                        and template_blk.tail.opcode == ida_hexrays.m_goto
                        and cur_ins.next is None
                    ):
                        break
                    cloned_ins = ida_hexrays.minsn_t(cur_ins)
                    cloned_ins.setaddr(mba.entry_ea)
                    instructions_to_copy.append(cloned_ins)
                    cur_ins = cur_ins.next

                # Create clone: last block is 0-way, others use shared_entry as
                # placeholder target (gives nsucc==1 so chain wiring works).
                cloned_blk = create_standalone_block(
                    template_blk,
                    instructions_to_copy,
                    target_serial=None if is_last else shared_entry_serial,
                    is_0_way=is_last,
                    verify=False,
                )
                cloned_serials.append(cloned_blk.serial)

                # Fix predecessors: remove any auto-inherited preds
                prev_pred_serials = [x for x in cloned_blk.predset]
                for prev_serial in prev_pred_serials:
                    cloned_blk.predset._del(prev_serial)

            # Fix stop-block relocation for all existing predecessors
            new_stop_serial = mba.qty - 1
            transient_stop_targets = set(cloned_serials)
            for stop_pred_serial in old_stop_pred_serials:
                stop_pred_blk = mba.get_mblock(stop_pred_serial)
                if stop_pred_blk is None or stop_pred_blk.serial in transient_stop_targets:
                    continue
                if (
                    stop_pred_blk.nsucc() != 1
                    or stop_pred_blk.succ(0) not in transient_stop_targets
                ):
                    continue
                if not change_1way_block_successor(
                    stop_pred_blk,
                    new_stop_serial,
                    verify=False,
                ):
                    logger.warning(
                        "private_terminal_suffix: failed to relocate stop pred blk[%d] -> blk[%d]",
                        stop_pred_blk.serial,
                        new_stop_serial,
                    )
                    return False

            # Wire the cloned chain: each non-last clone -> next clone
            for idx in range(len(cloned_serials) - 1):
                clone_blk = mba.get_mblock(cloned_serials[idx])
                next_clone_serial = cloned_serials[idx + 1]
                if clone_blk is None:
                    return False
                if not change_1way_block_successor(
                    clone_blk,
                    next_clone_serial,
                    verify=False,
                ):
                    logger.warning(
                        "private_terminal_suffix: failed to wire clone blk[%d] -> blk[%d]",
                        cloned_serials[idx],
                        next_clone_serial,
                    )
                    return False

            # Validate expected serials (informational only — clones already wired)
            if clone_expected_serials:
                for idx, (actual, expected) in enumerate(
                    zip(cloned_serials, clone_expected_serials, strict=False)
                ):
                    if actual != expected:
                        logger.info(
                            "private_terminal_suffix: clone[%d] got blk[%d], expected blk[%d] (non-fatal)",
                            idx,
                            actual,
                            expected,
                        )

            # Redirect anchor to first clone
            if not change_1way_block_successor(
                anchor_blk,
                cloned_serials[0],
                verify=False,
            ):
                logger.warning(
                    "private_terminal_suffix: failed to redirect anchor blk[%d] -> clone blk[%d]",
                    anchor_blk.serial,
                    cloned_serials[0],
                )
                return False

            logger.debug(
                "private_terminal_suffix: anchor=%d -> clone chain %s (from suffix %s)",
                anchor_blk.serial,
                cloned_serials,
                suffix_serials,
            )
            return True

        except Exception as exc:
            logger.error(
                "Exception in private_terminal_suffix for anchor=%d suffix=%s: %s",
                anchor_blk.serial,
                suffix_serials,
                exc,
            )
            import traceback
            logger.error("Traceback: %s", traceback.format_exc())
            return False

    def _apply_private_terminal_suffix_group(
        self,
        anchors: tuple[int, ...],
        shared_entry_serial: int,
        suffix_serials: tuple[int, ...],
        per_anchor_clone_expected_serials: tuple[tuple[int, ...], ...],
    ) -> bool:
        """Clone shared suffix chain for multiple anchors atomically.

        All clones are created first, then all anchors are redirected, and
        STOP predecessors are relocated once at the end.  This avoids serial
        drift that occurs when per-anchor PTS ops relocate STOP sequentially.

        Fail-closed: if any anchor validation fails before cloning starts,
        returns False immediately with no partial mutation.
        """
        mba = self.mba
        if mba is None:
            return False

        if not suffix_serials:
            logger.warning("private_terminal_suffix_group: empty suffix_serials")
            return False

        if not anchors:
            logger.warning("private_terminal_suffix_group: empty anchors")
            return False

        # ---- Phase 1: Validate ALL anchors (fail-closed, no partial apply) ----
        anchor_blks: list = []
        for anchor_serial in anchors:
            anchor_blk = mba.get_mblock(anchor_serial)
            if anchor_blk is None:
                logger.warning(
                    "private_terminal_suffix_group: anchor blk[%d] not found",
                    anchor_serial,
                )
                return False
            if anchor_blk.nsucc() != 1:
                logger.warning(
                    "private_terminal_suffix_group: anchor blk[%d] is not 1-way (nsucc=%d)",
                    anchor_serial,
                    anchor_blk.nsucc(),
                )
                return False
            current_succ = anchor_blk.succ(0)
            if current_succ != shared_entry_serial:
                logger.warning(
                    "private_terminal_suffix_group: anchor blk[%d] targets blk[%d], "
                    "expected shared_entry blk[%d]",
                    anchor_serial,
                    current_succ,
                    shared_entry_serial,
                )
                return False
            anchor_blks.append(anchor_blk)

        # ---- Phase 2: Validate suffix topology ONCE ----
        for idx, suffix_serial in enumerate(suffix_serials):
            suffix_blk = mba.get_mblock(suffix_serial)
            if suffix_blk is None:
                logger.warning(
                    "private_terminal_suffix_group: suffix blk[%d] not found",
                    suffix_serial,
                )
                return False
            if idx < len(suffix_serials) - 1:
                if suffix_blk.nsucc() != 1:
                    logger.warning(
                        "private_terminal_suffix_group: interior suffix blk[%d] "
                        "is not 1-way (nsucc=%d)",
                        suffix_serial,
                        suffix_blk.nsucc(),
                    )
                    return False
            else:
                if suffix_blk.nsucc() != 0:
                    logger.warning(
                        "private_terminal_suffix_group: final suffix blk[%d] "
                        "is not 0-way (nsucc=%d)",
                        suffix_serial,
                        suffix_blk.nsucc(),
                    )
                    return False

        try:
            # ---- Phase 3: Snapshot STOP predecessors ONCE ----
            old_stop_serial = mba.qty - 1
            old_stop_pred_serials = [
                serial
                for serial in range(mba.qty)
                if (blk := mba.get_mblock(serial)) is not None
                and blk.nsucc() == 1
                and blk.succ(0) == old_stop_serial
            ]
            logger.debug("PTS_DIAG Phase3: old_stop_pred_serials=%s, BLT_STOP_serial=%d, mba.qty=%d",
                          old_stop_pred_serials, suffix_serials[-1], mba.qty)

            # ---- Phase 4: Clone suffix chain for each anchor ----
            # Snapshot template blocks ONCE before cloning.  After the first
            # anchor's clones are inserted, mba.get_mblock(suffix_serial) may
            # return a clone (serial drift) instead of the original block.
            # The Python wrappers track the C++ mblock_t by identity, not serial.
            suffix_templates: list = []
            for suffix_serial in suffix_serials:
                tmpl = mba.get_mblock(suffix_serial)
                if tmpl is None:
                    logger.warning(
                        "private_terminal_suffix_group: suffix blk[%d] not found for template snapshot",
                        suffix_serial,
                    )
                    return False
                suffix_templates.append(tmpl)

            logger.debug("PTS_DIAG pre_Phase4: suffix_templates serials=%s, mba.qty=%d",
                          [t.serial for t in suffix_templates], mba.qty)

            per_anchor_first_clone: list[int] = []
            all_cloned_serials: set[int] = set()

            # Clone only interior suffix blocks (skip BLT_STOP — the last
            # serial).  Each anchor's last clone will wire directly to the
            # real BLT_STOP so IDA's structurer recognises the return path.
            interior_suffix_serials = suffix_serials[:-1]

            for anchor_idx, anchor_serial in enumerate(anchors):
                cloned_serials: list[int] = []
                for idx, suffix_serial in enumerate(interior_suffix_serials):
                    template_blk = suffix_templates[idx]

                    instructions_to_copy = []
                    cur_ins = template_blk.head
                    while cur_ins is not None:
                        if (
                            template_blk.nsucc() == 1
                            and template_blk.tail is not None
                            and template_blk.tail.opcode == ida_hexrays.m_goto
                            and cur_ins.next is None
                        ):
                            break
                        cloned_ins = ida_hexrays.minsn_t(cur_ins)
                        cloned_ins.setaddr(mba.entry_ea)
                        instructions_to_copy.append(cloned_ins)
                        cur_ins = cur_ins.next

                    cloned_blk = create_standalone_block(
                        template_blk,
                        instructions_to_copy,
                        target_serial=shared_entry_serial,
                        is_0_way=False,
                        verify=False,
                    )
                    logger.debug("PTS_DIAG Phase4: anchor[%d]=%d, suffix[%d]=%d, clone_serial=%d, clone.type=%d, "
                                  "clone.nsucc=%d, clone.npred=%d, mba.qty=%d, BLT_STOP_now=%d",
                                  anchor_idx, anchor_serial, idx, suffix_serial,
                                  cloned_blk.serial, cloned_blk.type, cloned_blk.nsucc(), cloned_blk.npred(),
                                  mba.qty, mba.qty - 1)
                    cloned_serials.append(cloned_blk.serial)
                    all_cloned_serials.add(cloned_blk.serial)

                    # Fix predecessors: remove any auto-inherited preds
                    prev_pred_serials = [x for x in cloned_blk.predset]
                    for prev_serial in prev_pred_serials:
                        cloned_blk.predset._del(prev_serial)

                # Wire the interior cloned chain for this anchor
                for idx in range(len(cloned_serials) - 1):
                    clone_blk = mba.get_mblock(cloned_serials[idx])
                    next_clone_serial = cloned_serials[idx + 1]
                    if clone_blk is None:
                        return False
                    wire_ok = change_1way_block_successor(
                        clone_blk,
                        next_clone_serial,
                        verify=False,
                    )
                    logger.debug("PTS_DIAG Phase4_wire: clone[%d]=%d -> clone[%d]=%d, ok=%s, "
                                  "clone_nsucc=%d, clone_succ0=%s",
                                  idx, cloned_serials[idx], idx + 1, next_clone_serial, wire_ok,
                                  clone_blk.nsucc(), clone_blk.succ(0) if clone_blk.nsucc() > 0 else -1)
                    if not wire_ok:
                        logger.debug("PTS_DIAG Phase4_wire FAILED: blk[%d].type=%d, nsucc=%d, npred=%d",
                                      cloned_serials[idx], clone_blk.type, clone_blk.nsucc(), clone_blk.npred())
                        logger.warning(
                            "private_terminal_suffix_group: failed to wire "
                            "clone blk[%d] -> blk[%d] for anchor blk[%d]",
                            cloned_serials[idx],
                            next_clone_serial,
                            anchor_serial,
                        )
                        return False

                # Wire last interior clone to real BLT_STOP
                last_clone_serial = cloned_serials[-1]
                last_clone_blk = mba.get_mblock(last_clone_serial)
                stop_serial = mba.qty - 1
                wire_ok = change_1way_block_successor(
                    last_clone_blk,
                    stop_serial,
                    verify=False,
                )
                logger.debug("PTS_DIAG Phase4_wire_to_stop: clone[%d]=%d -> BLT_STOP=%d, ok=%s",
                              len(cloned_serials) - 1, last_clone_serial, stop_serial, wire_ok)
                if not wire_ok:
                    return False

                per_anchor_first_clone.append(cloned_serials[0])

                # Validate expected serials (informational only)
                if per_anchor_clone_expected_serials and anchor_idx < len(per_anchor_clone_expected_serials):
                    expected = per_anchor_clone_expected_serials[anchor_idx]
                    for idx, (actual, exp) in enumerate(
                        zip(cloned_serials, expected, strict=False)
                    ):
                        if actual != exp:
                            logger.info(
                                "private_terminal_suffix_group: anchor blk[%d] "
                                "clone[%d] got blk[%d], expected blk[%d] (non-fatal)",
                                anchor_serial,
                                idx,
                                actual,
                                exp,
                            )

            logger.debug("PTS_DIAG post_Phase4: all_cloned_serials=%s, per_anchor_first=%s, mba.qty=%d",
                          sorted(all_cloned_serials), per_anchor_first_clone, mba.qty)

            # ---- Phase 5: Redirect ALL anchors to their first clones ----
            for anchor_idx, anchor_blk in enumerate(anchor_blks):
                redirect_ok = change_1way_block_successor(
                    anchor_blk,
                    per_anchor_first_clone[anchor_idx],
                    verify=False,
                )
                logger.debug("PTS_DIAG Phase5: anchor[%d]=%d -> first_clone=%d, ok=%s, "
                              "anchor_nsucc=%d, anchor_succ0=%s",
                              anchor_idx, anchor_blk.serial, per_anchor_first_clone[anchor_idx], redirect_ok,
                              anchor_blk.nsucc(), anchor_blk.succ(0) if anchor_blk.nsucc() > 0 else -1)
                if not redirect_ok:
                    logger.warning(
                        "private_terminal_suffix_group: failed to redirect "
                        "anchor blk[%d] -> clone blk[%d]",
                        anchor_blk.serial,
                        per_anchor_first_clone[anchor_idx],
                    )
                    return False

            # ---- Phase 6: Relocate STOP predecessors ONCE ----
            new_stop_serial = mba.qty - 1
            logger.debug("PTS_DIAG Phase6: new_stop_serial=%d, old_stop_pred_serials=%s, all_cloned=%s",
                          new_stop_serial, old_stop_pred_serials, sorted(all_cloned_serials))
            for stop_pred_serial in old_stop_pred_serials:
                stop_pred_blk = mba.get_mblock(stop_pred_serial)
                if stop_pred_blk is None or stop_pred_blk.serial in all_cloned_serials:
                    logger.debug("PTS_DIAG Phase6: skip pred_serial=%d (None=%s, in_cloned=%s)",
                                  stop_pred_serial, stop_pred_blk is None,
                                  stop_pred_serial in all_cloned_serials)
                    continue
                if (
                    stop_pred_blk.nsucc() != 1
                    or stop_pred_blk.succ(0) not in all_cloned_serials
                ):
                    logger.debug("PTS_DIAG Phase6: skip pred_blk[%d] nsucc=%d, succ0=%s, succ0_in_cloned=%s",
                                  stop_pred_blk.serial, stop_pred_blk.nsucc(),
                                  stop_pred_blk.succ(0) if stop_pred_blk.nsucc() > 0 else -1,
                                  stop_pred_blk.succ(0) in all_cloned_serials if stop_pred_blk.nsucc() > 0 else False)
                    continue
                old_succ = stop_pred_blk.succ(0)
                relocate_ok = change_1way_block_successor(
                    stop_pred_blk,
                    new_stop_serial,
                    verify=False,
                )
                logger.debug("PTS_DIAG Phase6: pred_blk[%d].succ(0)=%d -> new_stop=%d, ok=%s",
                              stop_pred_blk.serial, old_succ, new_stop_serial, relocate_ok)
                if not relocate_ok:
                    logger.warning(
                        "private_terminal_suffix_group: failed to relocate "
                        "stop pred blk[%d] -> blk[%d]",
                        stop_pred_blk.serial,
                        new_stop_serial,
                    )
                    return False

            logger.debug(
                "private_terminal_suffix_group: anchors=%s -> first_clones=%s (from suffix %s)",
                anchors,
                per_anchor_first_clone,
                suffix_serials,
            )
            logger.info("PTS group applied: %d anchors, %d clones, shared_entry=%d, stop=%d",
                        len(anchors), len(all_cloned_serials), shared_entry_serial, mba.qty - 1)
            return True

        except Exception as exc:
            logger.error(
                "Exception in private_terminal_suffix_group for anchors=%s suffix=%s: %s",
                anchors,
                suffix_serials,
                exc,
            )
            import traceback
            logger.error("Traceback: %s", traceback.format_exc())
            return False

    def _apply_direct_terminal_lowering_group(self, mba, mod) -> bool:
        """Apply grouped direct terminal lowering.

        Per-site lowering kinds:
        - RETURN_CONST: (v1: falls back to CLONE_MATERIALIZER)
        - CLONE_MATERIALIZER: clone materializer block(s) + wire to BLT_STOP
        - RETURN_FROM_SLOT/REG: (v2, falls back to CLONE_MATERIALIZER)

        Phases mirror PTS group backend:
        1. Validate anchors
        2. Validate suffix topology
        3. (skipped — DTL sites wire directly to BLT_STOP)
        4. Create private blocks per site
        5. Redirect anchors
        6. (skipped — no STOP relocation needed)
        """
        from d810.cfg.graph_modification import (
            DirectTerminalLoweringKind,
            DirectTerminalLoweringSite,
        )

        if mba is None:
            return False

        sites: tuple[DirectTerminalLoweringSite, ...] = mod.sites or ()
        suffix_serials: tuple[int, ...] = mod.suffix_serials or ()
        shared_entry_serial: int = mod.new_target

        if not sites:
            logger.warning("direct_terminal_lowering_group: empty sites")
            return False

        if not suffix_serials:
            logger.warning("direct_terminal_lowering_group: empty suffix_serials")
            return False

        # ---- Phase 1: Validate ALL anchors (fail-closed) ----
        anchor_blks: list = []
        for site in sites:
            anchor_blk = mba.get_mblock(site.anchor_serial)
            if anchor_blk is None:
                logger.warning(
                    "direct_terminal_lowering_group: anchor blk[%d] not found",
                    site.anchor_serial,
                )
                return False
            if anchor_blk.nsucc() != 1:
                logger.warning(
                    "direct_terminal_lowering_group: anchor blk[%d] is not 1-way (nsucc=%d)",
                    site.anchor_serial,
                    anchor_blk.nsucc(),
                )
                return False
            current_succ = anchor_blk.succ(0)
            if current_succ != shared_entry_serial:
                logger.warning(
                    "direct_terminal_lowering_group: anchor blk[%d] targets blk[%d], "
                    "expected shared_entry blk[%d]",
                    site.anchor_serial,
                    current_succ,
                    shared_entry_serial,
                )
                return False
            anchor_blks.append(anchor_blk)

        # ---- Phase 2: Validate suffix topology ----
        for idx, suffix_serial in enumerate(suffix_serials):
            suffix_blk = mba.get_mblock(suffix_serial)
            if suffix_blk is None:
                logger.warning(
                    "direct_terminal_lowering_group: suffix blk[%d] not found",
                    suffix_serial,
                )
                return False
            if idx < len(suffix_serials) - 1:
                if suffix_blk.nsucc() != 1:
                    logger.warning(
                        "direct_terminal_lowering_group: interior suffix blk[%d] "
                        "is not 1-way (nsucc=%d)",
                        suffix_serial,
                        suffix_blk.nsucc(),
                    )
                    return False
            else:
                # Last suffix block is BLT_STOP (0-way)
                if suffix_blk.nsucc() != 0:
                    logger.warning(
                        "direct_terminal_lowering_group: final suffix blk[%d] "
                        "is not 0-way (nsucc=%d)",
                        suffix_serial,
                        suffix_blk.nsucc(),
                    )
                    return False

        try:
            # Determine which blocks to clone per site.
            # Interior suffix = everything except BLT_STOP (last serial).
            interior_suffix_serials = suffix_serials[:-1]

            # Snapshot template blocks ONCE before cloning to avoid serial drift.
            suffix_templates: list = []
            for suffix_serial in interior_suffix_serials:
                tmpl = mba.get_mblock(suffix_serial)
                if tmpl is None:
                    logger.warning(
                        "direct_terminal_lowering_group: suffix blk[%d] not found for template snapshot",
                        suffix_serial,
                    )
                    return False
                suffix_templates.append(tmpl)

            logger.debug(
                "DTL_DIAG pre_Phase4: %d sites, interior_suffix=%s, mba.qty=%d",
                len(sites),
                interior_suffix_serials,
                mba.qty,
            )

            # ---- Phase 4: Create private blocks per site ----
            per_site_first_clone: list[int] = []

            for site_idx, site in enumerate(sites):
                # Determine materializer serials for this site.
                # For CLONE_MATERIALIZER: use site.materializer_serials
                # For RETURN_CONST (v1 fallback): use interior suffix serials
                # For RETURN_FROM_SLOT/REG (v2 fallback): use interior suffix serials
                if (
                    site.kind == DirectTerminalLoweringKind.CLONE_MATERIALIZER
                    and site.materializer_serials
                ):
                    clone_source_serials = site.materializer_serials
                    # Snapshot materializer templates for this site
                    site_templates: list = []
                    for ms in clone_source_serials:
                        t = mba.get_mblock(ms)
                        if t is None:
                            logger.warning(
                                "direct_terminal_lowering_group: materializer blk[%d] not found "
                                "for site anchor=%d",
                                ms,
                                site.anchor_serial,
                            )
                            return False
                        site_templates.append(t)
                else:
                    # Fallback: clone the full interior suffix chain
                    clone_source_serials = interior_suffix_serials
                    site_templates = list(suffix_templates)

                cloned_serials: list[int] = []
                for idx, source_serial in enumerate(clone_source_serials):
                    template_blk = site_templates[idx]

                    # Clone instructions (skip trailing goto — will be re-inserted)
                    instructions_to_copy = []
                    cur_ins = template_blk.head
                    while cur_ins is not None:
                        if (
                            template_blk.nsucc() == 1
                            and template_blk.tail is not None
                            and template_blk.tail.opcode == ida_hexrays.m_goto
                            and cur_ins.next is None
                        ):
                            break
                        cloned_ins = ida_hexrays.minsn_t(cur_ins)
                        cloned_ins.setaddr(mba.entry_ea)
                        instructions_to_copy.append(cloned_ins)
                        cur_ins = cur_ins.next

                    cloned_blk = create_standalone_block(
                        template_blk,
                        instructions_to_copy,
                        target_serial=shared_entry_serial,
                        is_0_way=False,
                        verify=False,
                    )
                    logger.debug(
                        "DTL_DIAG Phase4: site[%d] anchor=%d, source[%d]=%d, "
                        "clone_serial=%d, mba.qty=%d",
                        site_idx,
                        site.anchor_serial,
                        idx,
                        source_serial,
                        cloned_blk.serial,
                        mba.qty,
                    )
                    cloned_serials.append(cloned_blk.serial)

                    # Clean inherited predecessors
                    prev_pred_serials = [x for x in cloned_blk.predset]
                    for prev_serial in prev_pred_serials:
                        cloned_blk.predset._del(prev_serial)

                # Wire the cloned chain together
                for idx in range(len(cloned_serials) - 1):
                    clone_blk = mba.get_mblock(cloned_serials[idx])
                    next_clone_serial = cloned_serials[idx + 1]
                    if clone_blk is None:
                        return False
                    wire_ok = change_1way_block_successor(
                        clone_blk,
                        next_clone_serial,
                        verify=False,
                    )
                    if not wire_ok:
                        logger.warning(
                            "direct_terminal_lowering_group: failed to wire "
                            "clone blk[%d] -> blk[%d] for site anchor=%d",
                            cloned_serials[idx],
                            next_clone_serial,
                            site.anchor_serial,
                        )
                        return False

                # Wire last clone to real BLT_STOP
                last_clone_serial = cloned_serials[-1]
                last_clone_blk = mba.get_mblock(last_clone_serial)
                stop_serial = mba.qty - 1
                wire_ok = change_1way_block_successor(
                    last_clone_blk,
                    stop_serial,
                    verify=False,
                )
                logger.debug(
                    "DTL_DIAG Phase4_wire_to_stop: site[%d] anchor=%d, "
                    "clone[%d]=%d -> BLT_STOP=%d, ok=%s",
                    site_idx,
                    site.anchor_serial,
                    len(cloned_serials) - 1,
                    last_clone_serial,
                    stop_serial,
                    wire_ok,
                )
                if not wire_ok:
                    return False

                per_site_first_clone.append(cloned_serials[0])

            # ---- Phase 5: Redirect ALL anchors to their first clones ----
            for site_idx, anchor_blk in enumerate(anchor_blks):
                redirect_ok = change_1way_block_successor(
                    anchor_blk,
                    per_site_first_clone[site_idx],
                    verify=False,
                )
                logger.debug(
                    "DTL_DIAG Phase5: anchor[%d]=%d -> first_clone=%d, ok=%s",
                    site_idx,
                    anchor_blk.serial,
                    per_site_first_clone[site_idx],
                    redirect_ok,
                )
                if not redirect_ok:
                    logger.warning(
                        "direct_terminal_lowering_group: failed to redirect "
                        "anchor blk[%d] -> clone blk[%d]",
                        anchor_blk.serial,
                        per_site_first_clone[site_idx],
                    )
                    return False

            logger.info(
                "DTL group applied: %d sites, shared_entry=%d, stop=%d",
                len(sites),
                shared_entry_serial,
                mba.qty - 1,
            )
            return True

        except Exception as exc:
            logger.error(
                "Exception in direct_terminal_lowering_group for sites=%s suffix=%s: %s",
                [s.anchor_serial for s in sites],
                suffix_serials,
                exc,
            )
            import traceback
            logger.error("Traceback: %s", traceback.format_exc())
            return False

    def _apply_edge_split_trampoline(
        self,
        source_block_serial: int | None,
        via_pred: int | None,
        old_target: int | None,
        new_target: int | None,
        expected_serial: int | None,
    ) -> bool:
        """Materialize a standalone trampoline and redirect one predecessor to it."""
        if not self._check_edge_split_trampoline_preconditions(
            source_block_serial=source_block_serial,
            via_pred=via_pred,
            old_target=old_target,
            new_target=new_target,
        ):
            return False

        try:
            mba = self.mba
            if mba is None:
                return False
            src_blk = mba.get_mblock(source_block_serial)
            via_pred_blk = mba.get_mblock(via_pred)
            if src_blk is None or via_pred_blk is None:
                return False
            old_stop_serial = mba.qty - 1
            old_stop_pred_serials = [
                serial
                for serial in range(mba.qty)
                if (blk := mba.get_mblock(serial)) is not None
                and blk.nsucc() == 1
                and blk.succ(0) == old_stop_serial
            ]
            new_blk = create_standalone_block(
                src_blk,
                [],
                target_serial=new_target,
                is_0_way=False,
                verify=False,
            )
            if new_blk.serial != expected_serial:
                logger.warning(
                    "edge_split_trampoline: created blk[%d], expected blk[%d]",
                    new_blk.serial,
                    expected_serial,
                )
                return False
            new_stop_serial = mba.qty - 1
            for pred_serial in old_stop_pred_serials:
                pred_blk = mba.get_mblock(pred_serial)
                if pred_blk is None or pred_blk.serial == new_blk.serial:
                    continue
                if pred_blk.nsucc() != 1 or pred_blk.succ(0) != new_blk.serial:
                    continue
                if not change_1way_block_successor(pred_blk, new_stop_serial, verify=False):
                    logger.warning(
                        "edge_split_trampoline: failed to relocate stop predecessor blk[%d] -> blk[%d]",
                        pred_blk.serial,
                        new_stop_serial,
                    )
                    return False

            if not change_1way_block_successor(via_pred_blk, new_blk.serial, verify=False):
                logger.warning(
                    "edge_split_trampoline: failed to redirect pred=%d to blk[%d]",
                    via_pred_blk.serial,
                    new_blk.serial,
                )
                return False

            mba.mark_chains_dirty()
            logger.debug(
                "edge_split_trampoline: pred=%d -> %d -> %d (src=%d preserved)",
                via_pred_blk.serial,
                new_blk.serial,
                new_target,
                src_blk.serial,
            )
            return True

        except Exception as e:
            logger.error(
                "Exception in edge_split_trampoline for src=%d via_pred=%d: %s",
                source_block_serial,
                via_pred,
                e,
            )
            import traceback
            logger.error("Traceback: %s", traceback.format_exc())
            return False

    def _pre_reject_create_and_redirects(
        self,
        sorted_mods: list[GraphModification],
    ) -> tuple[list[GraphModification], int]:
        """Reject unsupported standalone block creation before live mutation."""
        filtered_mods: list[GraphModification] = []
        pre_rejected = 0

        for mod in sorted_mods:
            if mod.mod_type != ModificationType.BLOCK_CREATE_WITH_REDIRECT:
                filtered_mods.append(mod)
                continue
            if self._check_create_and_redirect_preconditions(
                source_block_serial=mod.block_serial,
                final_target_serial=mod.final_target,
            ):
                filtered_mods.append(mod)
                continue

            pre_rejected += 1
            logger.warning(
                "Pre-rejecting create_and_redirect before live apply: %s",
                mod.description,
            )

        if pre_rejected:
            logger.warning(
                "Pre-rejected %d create_and_redirect modification(s) before live apply",
                pre_rejected,
            )

        return filtered_mods, pre_rejected

    def _pre_reject_edge_split_trampolines(
        self,
        sorted_mods: list[GraphModification],
    ) -> tuple[list[GraphModification], int]:
        """Reject trampoline edits with illegal live preconditions before mutation."""
        filtered_mods: list[GraphModification] = []
        pre_rejected = 0

        for mod in sorted_mods:
            if mod.mod_type != ModificationType.EDGE_SPLIT_TRAMPOLINE:
                filtered_mods.append(mod)
                continue
            if self._check_edge_split_trampoline_preconditions(
                source_block_serial=mod.src_block,
                via_pred=mod.via_pred,
                old_target=mod.old_target,
                new_target=mod.new_target,
            ):
                filtered_mods.append(mod)
                continue

            pre_rejected += 1
            logger.warning(
                "Pre-rejecting edge_split_trampoline before live apply: %s",
                mod.description,
            )

        if pre_rejected:
            logger.warning(
                "Pre-rejected %d edge_split_trampoline modification(s) before live apply",
                pre_rejected,
            )

        return filtered_mods, pre_rejected

    def _pre_reject_duplicate_blocks(
        self,
        sorted_mods: list[GraphModification],
    ) -> tuple[list[GraphModification], int]:
        """Reject unsupported duplicate-block edits before live mutation."""
        filtered_mods: list[GraphModification] = []
        pre_rejected = 0

        for mod in sorted_mods:
            if mod.mod_type != ModificationType.BLOCK_DUPLICATE_AND_REDIRECT:
                filtered_mods.append(mod)
                continue
            if self._check_duplicate_block_preconditions(
                source_block_serial=mod.block_serial,
                pred_serial=mod.via_pred,
                target_serial=mod.new_target,
            ):
                filtered_mods.append(mod)
                continue

            pre_rejected += 1
            logger.warning(
                "Pre-rejecting duplicate_block before live apply: %s",
                mod.description,
            )

        if pre_rejected:
            logger.warning(
                "Pre-rejected %d duplicate_block modification(s) before live apply",
                pre_rejected,
            )

        return filtered_mods, pre_rejected

    def _check_create_and_redirect_preconditions(
        self,
        *,
        source_block_serial: int | None,
        final_target_serial: int | None,
    ) -> bool:
        """Validate live topology for create-and-redirect without mutating the MBA."""
        if self.mba is None or source_block_serial is None or final_target_serial is None:
            logger.warning(
                "create_and_redirect: incomplete parameters src=%s target=%s",
                source_block_serial,
                final_target_serial,
            )
            return False

        source_blk = self.mba.get_mblock(source_block_serial)
        target_blk = self.mba.get_mblock(final_target_serial)
        if source_blk is None or target_blk is None:
            logger.warning(
                "create_and_redirect: missing block src=%s target=%s",
                source_block_serial,
                final_target_serial,
            )
            return False

        if source_blk.serial == 0:
            logger.warning(
                "create_and_redirect: src blk[%d] is entry block and cannot be rewired safely",
                source_blk.serial,
            )
            return False

        if source_blk.nsucc() != 1:
            logger.warning(
                "create_and_redirect: src blk[%d] must be 1-way, got nsucc=%d",
                source_blk.serial,
                source_blk.nsucc(),
            )
            return False

        return True

    def _check_duplicate_block_preconditions(
        self,
        *,
        source_block_serial: int | None,
        pred_serial: int | None,
        target_serial: int | None,
    ) -> bool:
        """Validate duplicate-and-redirect topology without mutating the MBA."""
        if (
            self.mba is None
            or source_block_serial is None
            or pred_serial is None
        ):
            logger.warning(
                "duplicate_block: incomplete parameters src=%s pred=%s target=%s",
                source_block_serial,
                pred_serial,
                target_serial,
            )
            return False

        source_blk = self.mba.get_mblock(source_block_serial)
        pred_blk = self.mba.get_mblock(pred_serial)
        target_blk = self.mba.get_mblock(target_serial) if target_serial is not None else None

        if source_blk is None or pred_blk is None:
            logger.warning(
                "duplicate_block: missing block src=%s pred=%s",
                source_block_serial,
                pred_serial,
            )
            return False
        if target_serial is not None and target_blk is None:
            logger.warning(
                "duplicate_block: missing target blk[%s]",
                target_serial,
            )
            return False

            if source_blk.nsucc() > 2:
                logger.warning(
                    "duplicate_block: src blk[%d] has unsupported nsucc=%d",
                    source_blk.serial,
                    source_blk.nsucc(),
            )
            return False
        if source_blk.nsucc() == 2:
            if target_serial is not None:
                logger.warning(
                    "duplicate_block: src blk[%d] conditional duplicate does not support target override",
                    source_blk.serial,
                )
                return False
            if source_blk.tail is None or not ida_hexrays.is_mcode_jcond(source_blk.tail.opcode):
                logger.warning(
                    "duplicate_block: src blk[%d] has nsucc=2 but non-conditional tail",
                    source_blk.serial,
                )
                return False
            if source_blk.tail.d.t != ida_hexrays.mop_b:
                logger.warning(
                    "duplicate_block: src blk[%d] conditional tail lacks blkref operand",
                    source_blk.serial,
                )
                return False

        if pred_blk.nsucc() == 1:
            if pred_blk.succ(0) != source_blk.serial:
                logger.warning(
                    "duplicate_block: pred blk[%d] does not target src blk[%d]",
                    pred_blk.serial,
                    source_blk.serial,
                )
                return False
            return True

        if pred_blk.nsucc() == 2:
            if pred_blk.tail is None or not ida_hexrays.is_mcode_jcond(pred_blk.tail.opcode):
                logger.warning(
                    "duplicate_block: pred blk[%d] has nsucc=2 but non-conditional tail",
                    pred_blk.serial,
                )
                return False
            if pred_blk.tail.d.t != ida_hexrays.mop_b:
                logger.warning(
                    "duplicate_block: pred blk[%d] conditional tail lacks blkref operand",
                    pred_blk.serial,
                )
                return False
            if pred_blk.tail.d.b != source_blk.serial:
                logger.warning(
                    "duplicate_block: pred blk[%d] reaches src blk[%d] via fallthrough; unsupported",
                    pred_blk.serial,
                    source_blk.serial,
                )
                return False
            return True

        logger.warning(
            "duplicate_block: pred blk[%d] has unsupported nsucc=%d",
            pred_blk.serial,
            pred_blk.nsucc(),
        )
        return False

    def _check_edge_split_trampoline_preconditions(
        self,
        *,
        source_block_serial: int | None,
        via_pred: int | None,
        old_target: int | None,
        new_target: int | None,
    ) -> bool:
        """Validate live topology for a trampoline without mutating the MBA."""
        if (
            self.mba is None
            or source_block_serial is None
            or via_pred is None
            or old_target is None
            or new_target is None
        ):
            logger.warning(
                "edge_split_trampoline: incomplete parameters src=%s pred=%s old=%s new=%s",
                source_block_serial,
                via_pred,
                old_target,
                new_target,
            )
            return False

        mba = self.mba
        src_blk = mba.get_mblock(source_block_serial)
        via_pred_blk = mba.get_mblock(via_pred)
        target_blk = mba.get_mblock(new_target)

        if src_blk is None or via_pred_blk is None or target_blk is None:
            logger.warning(
                "edge_split_trampoline: missing block src=%s pred=%s target=%s",
                source_block_serial,
                via_pred,
                new_target,
            )
            return False

        if src_blk.tail is None or src_blk.tail.opcode != ida_hexrays.m_goto:
            logger.warning(
                "EDGE_SPLIT_ILLEGAL_PRECOND: src blk[%d] tail is not m_goto "
                "(old_target=%d, new_target=%d)",
                src_blk.serial,
                old_target,
                new_target,
            )
            return False
        if via_pred_blk.tail is None or via_pred_blk.tail.opcode != ida_hexrays.m_goto:
            logger.warning(
                "EDGE_SPLIT_ILLEGAL_PRECOND: via_pred blk[%d] tail is not m_goto "
                "(opcode=%s, src=%d, old_target=%d, new_target=%d)",
                via_pred_blk.serial,
                via_pred_blk.tail.opcode if via_pred_blk.tail is not None else "none",
                src_blk.serial,
                old_target,
                new_target,
            )
            return False

        if src_blk.nsucc() != 1:
            logger.warning(
                "edge_split_trampoline: src block %d has nsucc=%d, expected 1",
                src_blk.serial,
                src_blk.nsucc(),
            )
            return False
        if via_pred_blk.nsucc() != 1:
            logger.warning(
                "edge_split_trampoline: via_pred block %d has nsucc=%d, expected 1",
                via_pred_blk.serial,
                via_pred_blk.nsucc(),
            )
            return False
        if via_pred_blk.succ(0) != src_blk.serial:
            logger.warning(
                "edge_split_trampoline: via_pred block %d does not target src %d",
                via_pred_blk.serial,
                src_blk.serial,
            )
            return False
        if src_blk.succ(0) != old_target:
            logger.warning(
                "edge_split_trampoline: src block %d targets %d, expected old_target=%d",
                src_blk.serial,
                src_blk.succ(0),
                old_target,
            )
            return False

        return True

    def _apply_edge_redirect_via_pred_split(
        self,
        blk: "ida_hexrays.mblock_t",
        old_target: int,
        new_target: int,
        via_pred: int,
        clone_until: int | None,
    ) -> bool:
        """Clone ``blk`` and rewire ``via_pred``'s edge from ``blk`` to the clone.

        The clone then has its successor changed from ``old_target`` to
        ``new_target``.  The original ``blk`` keeps all other predecessors and
        its original successor.

        **Corridor case** (``clone_until`` is not None) is not yet implemented;
        this method returns False with a warning in that case.

        Args:
            blk: The block to clone (src_block).
            old_target: Current successor on blk being replaced on the clone.
            new_target: New successor for the clone.
            via_pred: Predecessor whose edge is rewired to the clone.
            clone_until: Future corridor endpoint (stub — not implemented).

        Returns:
            True on success, False on failure.
        """
        if clone_until is not None:
            logger.warning(
                "edge_redirect_via_pred_split: corridor cloning (clone_until=%d) "
                "is not yet implemented for block %d",
                clone_until, blk.serial,
            )
            return False

        mba = self.mba

        # ── Legality gate ──────────────────────────────────────────────
        # Both blocks must have explicit tails with expected opcodes.
        if blk.tail is None or blk.tail.opcode != ida_hexrays.m_goto:
            logger.warning(
                "EDGE_SPLIT_ILLEGAL_PRECOND: src blk[%d] tail is not m_goto "
                "(old_target=%d, new_target=%d)",
                blk.serial, old_target, new_target,
            )
            return False

        via_pred_blk_pre = mba.get_mblock(via_pred)
        if via_pred_blk_pre is not None:
            _vp_tail = via_pred_blk_pre.tail
            if _vp_tail is None:
                logger.warning(
                    "EDGE_SPLIT_ILLEGAL_PRECOND: via_pred blk[%d] has no tail "
                    "(src=%d, old_target=%d, new_target=%d)",
                    via_pred, blk.serial, old_target, new_target,
                )
                return False
            if _vp_tail.opcode != ida_hexrays.m_goto:
                logger.warning(
                    "EDGE_SPLIT_ILLEGAL_PRECOND: via_pred blk[%d] tail is not m_goto "
                    "(opcode=%d, src=%d, old_target=%d, new_target=%d)",
                    via_pred, _vp_tail.opcode, blk.serial, old_target, new_target,
                )
                return False

        # via_pred must currently target src
        if via_pred_blk_pre is not None:
            _vp_targets_src = any(
                via_pred_blk_pre.succset[i] == blk.serial
                for i in range(via_pred_blk_pre.succset.size())
            )
            if not _vp_targets_src:
                logger.warning(
                    "EDGE_SPLIT_ILLEGAL_PRECOND: via_pred blk[%d] does not target src blk[%d] "
                    "(old_target=%d, new_target=%d)",
                    via_pred, blk.serial, old_target, new_target,
                )
                return False

        # ── Original preconditions ─────────────────────────────────────
        # Guard: src_block must be 1-way (clone inherits its successor).
        if blk.nsucc() != 1:
            logger.warning(
                "src_block %d has %d successors, expected 1", blk.serial, blk.nsucc()
            )
            return False
        if new_target == blk.serial:
            logger.warning(
                "edge_redirect_via_pred_split: rejecting self-loop redirect src=%d -> %d",
                blk.serial, new_target,
            )
            return False

        via_pred_blk = mba.get_mblock(via_pred)
        if via_pred_blk is None:
            logger.warning("via_pred block %d not found", via_pred)
            return False
        if via_pred_blk.nsucc() != 1:
            logger.warning(
                "via_pred block %d has %d successors, expected 1",
                via_pred, via_pred_blk.nsucc(),
            )
            return False
        if not any(blk.predset[i] == via_pred for i in range(blk.predset.size())):
            logger.warning(
                "via_pred %d is not a predecessor of src_block %d", via_pred, blk.serial
            )
            return False

        try:
            logger.info(
                "EDGE_SPLIT_PRE: src_blk=%d src_npred=%d via_pred=%d"
                " via_pred_npred=%d old_target=%d new_target=%d",
                blk.serial,
                blk.npred(),
                via_pred,
                via_pred_blk.npred(),
                old_target if old_target is not None else -1,
                new_target,
            )

            # Direct redirect: rewire via_pred -> new_target.
            # change_1way_block_successor handles all bookkeeping:
            #   - Updates via_pred_blk.succset (removes old, adds new)
            #   - Removes via_pred from blk.predset
            #   - Adds via_pred to new_target.predset
            #   - Updates the goto instruction's blkref
            #   - Marks dirty
            if not change_1way_block_successor(via_pred_blk, new_target, verify=False):
                logger.warning(
                    "edge_redirect_via_pred_split: failed to rewire pred=%d to %d",
                    via_pred, new_target,
                )
                return False

            mba.mark_chains_dirty()

            logger.debug(
                "edge_redirect_via_pred_split: done — pred=%d -> %d "
                "(original blk=%d -> %d preserved)",
                via_pred, new_target, blk.serial, old_target,
            )
            return True

        except Exception as e:
            logger.error(
                "Exception in edge_redirect_via_pred_split for block %d: %s",
                blk.serial, e,
            )
            import traceback
            logger.error("Traceback: %s", traceback.format_exc())
            return False


@dataclass
class ImmediateGraphModifier:
    """
    Graph modifier that applies changes immediately instead of batching them.

    .. warning::

        Use with caution! Immediate modification can cause stale pointer bugs
        when other rules are analyzing the same CFG. Prefer DeferredGraphModifier
        for most use cases.

    This provides the same interface as DeferredGraphModifier but applies
    each modification immediately when queue_* is called. The apply() method
    runs cleanup (optimize_local, verify) but changes are already applied.

    When to Use::

        # SAFE: Single-block analysis, no iteration over other blocks
        class SimplePeepholeOptimizer(GenericRule):
            def optimize(self, blk: mblock_t) -> int:
                modifier = ImmediateGraphModifier(self.mba)
                if blk.tail and blk.tail.opcode == m_goto:
                    modifier.queue_goto_change(blk.serial, optimized_target)
                return modifier.apply()

    When NOT to Use::

        # UNSAFE: Multi-block iteration - use DeferredGraphModifier instead!
        class UnsafeOptimizer(GenericRule):
            def optimize(self, blk: mblock_t) -> int:
                modifier = ImmediateGraphModifier(self.mba)
                for serial in range(self.mba.qty):  # Iterating all blocks
                    block = self.mba.get_mblock(serial)
                    modifier.queue_goto_change(...)  # DANGER: may invalidate
                    # blocks we haven't visited yet!
                return modifier.apply()

    Basic Usage::

        modifier = ImmediateGraphModifier(mba)

        # Modifications are applied immediately
        modifier.queue_goto_change(block_serial=10, new_target=20)
        modifier.queue_convert_to_goto(block_serial=15, goto_target=25)

        # apply() runs cleanup, changes already applied
        modifier.apply()

    See module docstring for complete examples and best practices.
    """
    mba: ida_hexrays.mba_t
    modifications_applied: int = 0
    _applied: bool = False
    verify_failed: bool = False

    def reset(self) -> None:
        """Reset the modifier state."""
        self.modifications_applied = 0
        self._applied = False

    def queue_goto_change(
        self,
        block_serial: int,
        new_target: int,
        description: str = "",
    ) -> None:
        """Apply a change to an unconditional goto's destination immediately."""
        blk = self.mba.get_mblock(block_serial)
        if blk is None:
            logger.warning("Block %d not found", block_serial)
            return

        logger.debug("Immediate goto change: block %d -> %d", block_serial, new_target)
        if self._apply_goto_change(blk, new_target):
            self.modifications_applied += 1

    def queue_conditional_target_change(
        self,
        block_serial: int,
        new_target: int,
        description: str = "",
    ) -> None:
        """Apply a change to a conditional jump's target immediately."""
        blk = self.mba.get_mblock(block_serial)
        if blk is None:
            logger.warning("Block %d not found", block_serial)
            return

        logger.debug("Immediate target change: block %d -> %d", block_serial, new_target)
        if self._apply_target_change(blk, new_target):
            self.modifications_applied += 1

    def queue_convert_to_goto(
        self,
        block_serial: int,
        goto_target: int,
        description: str = "",
    ) -> None:
        """Convert a 2-way block to a 1-way goto immediately."""
        blk = self.mba.get_mblock(block_serial)
        if blk is None:
            logger.warning("Block %d not found", block_serial)
            return

        logger.debug("Immediate convert to goto: block %d -> %d", block_serial, goto_target)
        if self._apply_convert_to_goto(blk, goto_target):
            self.modifications_applied += 1

    def queue_insn_remove(
        self,
        block_serial: int,
        insn_ea: int,
        description: str = "",
    ) -> None:
        """Remove a specific instruction immediately."""
        blk = self.mba.get_mblock(block_serial)
        if blk is None:
            logger.warning("Block %d not found", block_serial)
            return

        logger.debug("Immediate insn remove: block %d, ea=%s", block_serial, hex(insn_ea))
        if self._apply_insn_remove(blk, insn_ea):
            self.modifications_applied += 1

    def queue_insn_nop(
        self,
        block_serial: int,
        insn_ea: int,
        description: str = "",
    ) -> None:
        """NOP a specific instruction immediately."""
        blk = self.mba.get_mblock(block_serial)
        if blk is None:
            logger.warning("Block %d not found", block_serial)
            return

        logger.debug("Immediate insn nop: block %d, ea=%s", block_serial, hex(insn_ea))
        if self._apply_insn_nop(blk, insn_ea):
            self.modifications_applied += 1

    def queue_create_and_redirect(
        self,
        source_block_serial: int,
        final_target_serial: int,
        instructions_to_copy: list | tuple,
        is_0_way: bool = False,
        expected_serial: int | None = None,
        description: str = "",
    ) -> None:
        """Create an intermediate block and redirect immediately."""
        blk = self.mba.get_mblock(source_block_serial)
        if blk is None:
            logger.warning("Block %d not found", source_block_serial)
            return

        logger.debug(
            "Immediate create_and_redirect: %d -> (new) -> %d with %d instructions",
            source_block_serial, final_target_serial, len(instructions_to_copy)
        )
        if self._apply_create_and_redirect(
            blk,
            final_target_serial,
            instructions_to_copy,
            is_0_way,
            expected_serial=expected_serial,
        ):
            self.modifications_applied += 1

    def queue_remove_edge(
        self,
        from_serial: int,
        to_serial: int,
        description: str = "",
    ) -> None:
        """Remove a single edge immediately."""
        blk = self.mba.get_mblock(from_serial)
        if blk is None:
            logger.warning("Block %d not found", from_serial)
            return

        logger.debug("Immediate remove edge: %d -> %d", from_serial, to_serial)
        if self._apply_remove_edge(blk, to_serial):
            self.modifications_applied += 1

    def has_modifications(self) -> bool:
        """Check if any modifications were applied."""
        return self.modifications_applied > 0

    def apply(
        self,
        run_optimize_local: bool = True,
        run_deep_cleaning: bool = False,
    ) -> int:
        """
        No-op apply method since changes are already applied.

        Args:
            run_optimize_local: If True, call mba.optimize_local(0)
            run_deep_cleaning: If True, run mba_deep_cleaning

        Returns:
            Number of modifications that were applied immediately
        """
        if self._applied:
            logger.warning("ImmediateGraphModifier.apply() called twice")
            return 0

        logger.info(
            "ImmediateGraphModifier.apply(): %d modifications already applied",
            self.modifications_applied
        )

        if self.modifications_applied > 0:
            self.mba.mark_chains_dirty()

            if run_deep_cleaning:
                mba_deep_cleaning(self.mba, call_mba_combine_block=True)
            elif run_optimize_local:
                self.mba.optimize_local(0)

            try:
                safe_verify(
                    self.mba,
                    "after immediate modifications",
                    logger_func=logger.error,
                )
            except RuntimeError:
                self.verify_failed = True
                logger.warning(
                    "MBA verify failed after applying %d immediate modifications "
                    "-- marking verify_failed so callers can abort gracefully",
                    self.modifications_applied,
                )

        self._applied = True
        return self.modifications_applied

    # Reuse the same implementation methods from DeferredGraphModifier
    def _apply_goto_change(self, blk: ida_hexrays.mblock_t, new_target: int) -> bool:
        """Redirect a 1-way block successor (tail may be non-goto)."""
        if blk.nsucc() != 1:
            logger.warning(
                "Block %d is not 1-way (nsucc=%d)",
                blk.serial,
                blk.nsucc(),
            )
            return False

        return change_1way_block_successor(blk, new_target, verify=False)

    def _apply_target_change(self, blk: ida_hexrays.mblock_t, new_target: int) -> bool:
        """Change a conditional jump's target."""
        if blk.tail is None:
            return False

        # Check if it's a conditional jump
        if blk.tail.opcode not in [
            ida_hexrays.m_jnz, ida_hexrays.m_jz,
            ida_hexrays.m_jae, ida_hexrays.m_jb,
            ida_hexrays.m_ja, ida_hexrays.m_jbe,
            ida_hexrays.m_jg, ida_hexrays.m_jge,
            ida_hexrays.m_jl, ida_hexrays.m_jle,
        ]:
            logger.warning(
                "Block %d doesn't end with conditional jump",
                blk.serial
            )
            return False

        return change_2way_block_conditional_successor(blk, new_target, verify=False)

    def _apply_convert_to_goto(self, blk: ida_hexrays.mblock_t, goto_target: int) -> bool:
        """Convert a 2-way block to a 1-way goto."""
        return make_2way_block_goto(blk, goto_target, verify=False)

    def _apply_remove_edge(self, blk: ida_hexrays.mblock_t, to_serial: int) -> bool:
        """Remove a single outgoing edge from *blk* to *to_serial*."""
        return remove_block_edge(blk, to_serial, verify=False)

    def _apply_insn_remove(self, blk: ida_hexrays.mblock_t, insn_ea: int) -> bool:
        """Remove an instruction by its EA."""
        insn = blk.head
        while insn:
            if insn.ea == insn_ea:
                blk.remove_from_block(insn)
                return True
            insn = insn.next

        logger.warning(
            "Instruction at EA %s not found in block %d",
            hex(insn_ea), blk.serial
        )
        return False

    def _apply_insn_nop(self, blk: ida_hexrays.mblock_t, insn_ea: int) -> bool:
        """NOP an instruction by its EA."""
        insn = blk.head
        while insn:
            if insn.ea == insn_ea:
                blk.make_nop(insn)
                return True
            insn = insn.next

        logger.warning(
            "Instruction at EA %s not found in block %d",
            hex(insn_ea), blk.serial
        )
        return False

    def _apply_create_and_redirect(
        self,
        source_blk: ida_hexrays.mblock_t,
        final_target: int,
        instructions_to_copy: list | tuple | None,
        is_0_way: bool,
        expected_serial: int | None,
    ) -> bool:
        """
        Create a standalone intermediate block and redirect source through it.

        Creates: source_blk -> new_block -> final_target

        Uses :func:`create_standalone_block` instead of :func:`create_block`
        to avoid corrupting ``ref_block``'s CFG edges (INTERR 50856/50858).
        """
        if instructions_to_copy is None:
            instructions_to_copy = []
        instructions_to_copy = _prepare_block_creation_instructions(
            self.mba,
            instructions_to_copy,
        )
        if source_blk.serial == 0:
            logger.warning(
                "create_and_redirect requires non-entry source block; block %d is entry",
                source_blk.serial,
            )
            return False

        mba = self.mba

        # Find reference block for copy_block template (tail block, avoiding XTRN/STOP)
        tail_serial = mba.qty - 1
        ref_block = mba.get_mblock(tail_serial)
        while ref_block.type in (ida_hexrays.BLT_XTRN, ida_hexrays.BLT_STOP):
            tail_serial -= 1
            ref_block = mba.get_mblock(tail_serial)

        # Get target block to check if it's 0-way
        target_blk = mba.get_mblock(final_target)
        actual_is_0_way = is_0_way or (target_blk and target_blk.type == ida_hexrays.BLT_0WAY)

        try:
            old_stop_serial = mba.qty - 1
            old_stop_pred_serials = [
                serial
                for serial in range(mba.qty)
                if (blk := mba.get_mblock(serial)) is not None
                and blk.nsucc() == 1
                and blk.succ(0) == old_stop_serial
            ]
            # Create a standalone block -- ref_block's CFG edges are NOT modified.
            new_block = create_standalone_block(
                ref_block,
                instructions_to_copy,
                target_serial=None if actual_is_0_way else final_target,
                is_0_way=actual_is_0_way,
                verify=False,
            )
            if expected_serial is not None and new_block.serial != expected_serial:
                logger.warning(
                    "create_and_redirect: created blk[%d], expected blk[%d]",
                    new_block.serial,
                    expected_serial,
                )
                return False
            new_stop_serial = mba.qty - 1
            for pred_serial in old_stop_pred_serials:
                pred_blk = mba.get_mblock(pred_serial)
                if pred_blk is None or pred_blk.serial == new_block.serial:
                    continue
                if pred_blk.nsucc() != 1 or pred_blk.succ(0) != new_block.serial:
                    continue
                if not change_1way_block_successor(pred_blk, new_stop_serial, verify=False):
                    logger.warning(
                        "create_and_redirect: failed to relocate stop predecessor blk[%d] -> blk[%d]",
                        pred_blk.serial,
                        new_stop_serial,
                    )
                    return False

            # Ensure all instructions in the new block have safe EAs within
            # the function range to prevent INTERR 50863.
            safe_ea = mba.entry_ea
            cur = new_block.head
            while cur is not None:
                cur.ea = safe_ea
                cur = cur.next

            # Redirect source block to the new block
            if not change_1way_block_successor(source_blk, new_block.serial, verify=False):
                logger.warning(
                    "Failed to redirect block %d to new block %d",
                    source_blk.serial, new_block.serial
                )
                return False

            logger.debug(
                "Created block %d: %d -> %d -> %d",
                new_block.serial, source_blk.serial, new_block.serial, final_target
            )
            return True

        except Exception as e:
            logger.error(
                "Exception in create_and_redirect for block %d: %s",
                source_blk.serial, e
            )
            return False
