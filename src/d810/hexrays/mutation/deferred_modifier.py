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
    _rewire_edge)
from d810.cfg.flowgraph import PortableCFG
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
    EDGE_REDIRECT_VIA_PRED_SPLIT = auto()  # Clone src block; redirect one predecessor to clone


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
    # For EDGE_REDIRECT_VIA_PRED_SPLIT: block to clone
    src_block: int | None = None
    # For EDGE_REDIRECT_VIA_PRED_SPLIT: current successor being replaced on clone
    old_target: int | None = None
    # For EDGE_REDIRECT_VIA_PRED_SPLIT: predecessor whose edge gets redirected to clone
    via_pred: int | None = None
    # For EDGE_REDIRECT_VIA_PRED_SPLIT: future corridor cloning endpoint (unused, stub)
    clone_until: int | None = None
    # How to resolve new_target at apply-time
    target_ref_kind: TargetRefKind = TargetRefKind.ABSOLUTE


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
    _pre_snapshot: PortableCFG | None = None
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
        instructions_to_copy: list,
        is_0_way: bool = False,
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
            instructions_to_copy: List of minsn_t to copy to the new block
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
            description: Optional description for logging
        """
        self.modifications.append(GraphModification(
            mod_type=ModificationType.BLOCK_CREATE_WITH_CONDITIONAL_REDIRECT,
            block_serial=source_blk_serial,
            new_target=ref_blk_serial,  # Reference block to copy from
            conditional_target=conditional_target_serial,
            fallthrough_target=fallthrough_target_serial,
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

    def has_modifications(self) -> bool:
        """Check if there are any queued modifications."""
        return len(self.modifications) > 0

    def _restore_from_snapshot(self, snapshot: PortableCFG) -> bool:
        """Restore MBA topology from a PortableCFG snapshot.

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
            elif mod.mod_type == ModificationType.EDGE_REDIRECT_VIA_PRED_SPLIT:
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
                    if mod_type == ModificationType.EDGE_REDIRECT_VIA_PRED_SPLIT:
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
        }
        terminal_type_rank = {
            ModificationType.BLOCK_GOTO_CHANGE: 1,
            ModificationType.BLOCK_TARGET_CHANGE: 2,
            ModificationType.BLOCK_CONVERT_TO_GOTO: 3,
            ModificationType.BLOCK_CREATE_WITH_REDIRECT: 4,
            ModificationType.BLOCK_CREATE_WITH_CONDITIONAL_REDIRECT: 5,
            # EDGE_REDIRECT_VIA_PRED_SPLIT is intentionally absent: it is not
            # in terminal_mod_types (it executes via a separate code path in
            # apply_modifications) so ranking it here would cause it to be
            # incorrectly processed by the terminal-type conflict pass.
        }

        # Edge-type conflict resolution: for EDGE_REDIRECT_VIA_PRED_SPLIT,
        # group by (src_block, old_target, via_pred) and keep highest rule_priority.
        # This must run BEFORE the general terminal-type pass below so that survivors
        # are correctly evaluated in the mixed-type pass.
        edge_type = ModificationType.EDGE_REDIRECT_VIA_PRED_SPLIT
        edge_mods = [m for m in unique_modifications if m.mod_type == edge_type]
        if edge_mods:
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
                    "EDGE CONFLICT RESOLVED: src=%d old=%d via_pred=%d - keeping "
                    "new_target=%d (rule_priority=%d), discarding %s",
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

        logger.info("Applying %d queued graph modifications", len(sorted_mods))

        if self.event_emitter is not None:
            self._emit(DeferredEvent.DEFERRED_APPLY_STARTED, {
                **self._base_payload(),
                "modification_count": len(sorted_mods),
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
        failed = 0
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
            successful, len(sorted_mods), failed, rolled_back
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
                    logger.error("post_apply_hook raised: %s", e, exc_info=True)
                    capture_failure_artifact(
                        self.mba,
                        "exception during deferred post-apply hook",
                        e,
                        logger_func=logger.error,
                        capture_metadata={
                            "phase": "post_apply_hook_exception",
                            "applied_modifications": successful,
                            "queued_modifications": len(sorted_mods),
                            "recent_modifications": list(recent_modifications),
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
            # The clone block created by duplicate_block cannot be removed
            # (no API to delete a block), so it remains as dead code.
            src_block = mod.src_block
            via_pred = mod.via_pred
            if src_block is None or via_pred is None:
                return None

            def _rollback_edge_redirect() -> bool:
                pred_blk = self.mba.get_mblock(via_pred)
                src_blk = self.mba.get_mblock(src_block)
                if pred_blk is None or src_blk is None:
                    return False
                # We don't know the clone serial post-hoc, so scan pred_blk's
                # succset for a block that is NOT src_block and rewire back.
                # This is best-effort; may fail if topology has changed further.
                logger.warning(
                    "edge_redirect_via_pred_split rollback: rewiring pred=%d "
                    "back to src=%d (clone block remains as dead code)",
                    via_pred, src_block,
                )
                # Remove any successor that is not src_block from pred_blk succset,
                # add src_block back.
                succs = [pred_blk.succset[i] for i in range(pred_blk.succset.size())]
                for s in succs:
                    if s != src_block:
                        pred_blk.succset._del(s)
                        clone_blk = self.mba.get_mblock(s)
                        if clone_blk is not None:
                            clone_blk.predset._del(via_pred)
                if not any(
                    pred_blk.succset[i] == src_block
                    for i in range(pred_blk.succset.size())
                ):
                    pred_blk.succset.push_back(src_block)
                if not any(
                    src_blk.predset[i] == via_pred
                    for i in range(src_blk.predset.size())
                ):
                    src_blk.predset.push_back(via_pred)
                pred_blk.mark_lists_dirty()
                src_blk.mark_lists_dirty()
                self.mba.mark_chains_dirty()
                return True

            return (
                f"rollback edge_redirect pred={via_pred} -> src={src_block}",
                _rollback_edge_redirect,
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
                blk, mod.final_target, mod.instructions_to_copy, mod.is_0_way
            )

        elif mod.mod_type == ModificationType.BLOCK_CREATE_WITH_CONDITIONAL_REDIRECT:
            return self._apply_create_conditional_redirect(
                blk, mod.new_target, mod.conditional_target, mod.fallthrough_target
            )

        elif mod.mod_type == ModificationType.EDGE_REDIRECT_VIA_PRED_SPLIT:
            return self._apply_edge_redirect_via_pred_split(
                blk, mod.old_target, mod.new_target, mod.via_pred, mod.clone_until
            )

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
        instructions_to_copy: list,
        is_0_way: bool,
    ) -> bool:
        """
        Create a standalone intermediate block and redirect source through it.

        Creates: source_blk -> new_block -> final_target

        Uses :func:`create_standalone_block` instead of :func:`create_block`
        to avoid corrupting ``ref_block``'s CFG edges (INTERR 50856/50858).
        """
        if not instructions_to_copy:
            logger.warning(
                "No instructions to copy for create_and_redirect on block %d",
                source_blk.serial
            )
            return False

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
            # Create a standalone block -- ref_block's CFG edges are NOT modified.
            new_block = create_standalone_block(
                ref_block,
                instructions_to_copy,
                target_serial=None if actual_is_0_way else final_target,
                is_0_way=actual_is_0_way,
                verify=False,
            )

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

        # Preconditions
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
            # Step 1: Clone the source block.
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
            clone_blk, nop_or_none = duplicate_block(blk, verify=False)
            logger.debug(
                "edge_redirect_via_pred_split: cloned block %d -> clone %d",
                blk.serial, clone_blk.serial,
            )

            # Step 2: Clear clone predset.
            # Use _del() — the standard API used throughout this codebase (e.g.
            # duplicate_block in cfg_mutations.py); predset has no .empty()/.pop_back().
            while clone_blk.predset.size() > 0:
                clone_blk.predset._del(clone_blk.predset[0])

            # Step 3: Guard clone shape — must be 1-way to allow redirect.
            # If duplicate_block produced a non-1-way clone, the clone is
            # disconnected (no preds yet) so leaving it is harmless.
            if clone_blk.nsucc() != 1:
                logger.warning(
                    "edge_redirect_via_pred_split: clone %d has %d successors, expected 1",
                    clone_blk.serial, clone_blk.nsucc(),
                )
                return False

            # Step 4: Redirect clone -> new_target BEFORE rewiring via_pred.
            # This keeps the graph consistent: if this step fails, via_pred still
            # points at blk (original state), so no partial mutation occurs.
            if old_target is not None:
                clone_succ = [clone_blk.succset[i] for i in range(clone_blk.succset.size())]
                if old_target not in clone_succ:
                    logger.warning(
                        "Clone %d does not have expected successor %d",
                        clone_blk.serial, old_target,
                    )
                    return False

            if not change_1way_block_successor(clone_blk, new_target, verify=False):
                logger.warning(
                    "edge_redirect_via_pred_split: failed to redirect clone %d "
                    "from %d to %d",
                    clone_blk.serial, old_target, new_target,
                )
                return False

            # Step 5: Only now rewire via_pred -> clone.  The graph is only
            # mutated from via_pred's perspective once the clone is fully set up.
            if not change_1way_block_successor(via_pred_blk, clone_blk.serial, verify=False):
                logger.warning(
                    "edge_redirect_via_pred_split: failed to rewire pred=%d to clone=%d",
                    via_pred, clone_blk.serial,
                )
                return False
            # Remove via_pred from blk's predset (change_1way_block_successor wired
            # via_pred -> clone, but blk.predset still contains via_pred).
            blk.predset._del(via_pred)

            # Step 6: Fix via_pred's tail instruction blkref if it references blk.
            pred_blk = via_pred_blk
            if pred_blk.tail is not None:
                tail = pred_blk.tail
                # For m_goto: l operand holds the target block serial
                if tail.opcode == ida_hexrays.m_goto and tail.l.t == ida_hexrays.mop_b:
                    if tail.l.b == blk.serial:
                        tail.l.b = clone_blk.serial
                # For conditional jumps: d operand holds the taken-branch target
                elif ida_hexrays.is_mcode_jcond(tail.opcode) and tail.d.t == ida_hexrays.mop_b:
                    if tail.d.b == blk.serial:
                        tail.d.b = clone_blk.serial

            pred_blk.mark_lists_dirty()
            blk.mark_lists_dirty()
            clone_blk.mark_lists_dirty()

            # Step 7: Mark chains dirty so IDA rebuilds def-use.
            mba.mark_chains_dirty()

            logger.debug(
                "edge_redirect_via_pred_split: done — pred=%d -> clone=%d -> %d "
                "(original blk=%d -> %d preserved)",
                via_pred, clone_blk.serial, new_target, blk.serial, old_target,
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
        instructions_to_copy: list,
        is_0_way: bool = False,
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
            blk, final_target_serial, instructions_to_copy, is_0_way
        ):
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
        instructions_to_copy: list,
        is_0_way: bool,
    ) -> bool:
        """
        Create a standalone intermediate block and redirect source through it.

        Creates: source_blk -> new_block -> final_target

        Uses :func:`create_standalone_block` instead of :func:`create_block`
        to avoid corrupting ``ref_block``'s CFG edges (INTERR 50856/50858).
        """
        if not instructions_to_copy:
            logger.warning(
                "No instructions to copy for create_and_redirect on block %d",
                source_blk.serial
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
            # Create a standalone block -- ref_block's CFG edges are NOT modified.
            new_block = create_standalone_block(
                ref_block,
                instructions_to_copy,
                target_serial=None if actual_is_0_way else final_target,
                is_0_way=actual_is_0_way,
                verify=False,
            )

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
