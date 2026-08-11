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

    class MyDeferredOptimizer(FlowOptimizationRule):
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

    class MyImmediateOptimizer(FlowOptimizationRule):
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
- Computed-state transition evidence: read-only dispatcher target resolution
- Conditional-clone rewrites: deferred predecessor repair example
- Deferred graph modification: orchestrates ordered CFG mutation rules
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from enum import Enum, auto
import hashlib
import re
import uuid

from d810.core.typing import TYPE_CHECKING, Callable, Iterable
import os
import time

import ida_hexrays
import ida_ida
import ida_typeinf
import idaapi

from d810.core import getLogger
from d810.hexrays.mutation.block_retention import release_committed_block_retention
from d810.hexrays.mutation.deferred_events import DeferredEvent, EventEmitter
from d810.hexrays.mutation.mba_mutation_events import (
    MbaMutationGateway,
    MbaMutationPlanItem,
    StructuralMutationKind,
)
from d810.hexrays.mutation.semantic_fragment_backend import (
    SemanticFragmentBackendRejected,
    SemanticFragmentBackendState,
    SemanticFragmentRootEdgeBinding,
    SemanticFragmentRootPublicationGroup,
    SemanticFragmentRootPublicationToken,
    SemanticNativeBodyMaterializer,
    discard_staged_semantic_fragment,
    finalize_semantic_fragment_for_commit,
    observe_published_semantic_fragment_graph,
    observe_staged_semantic_fragment,
    plan_semantic_fragment_root_inventory,
    prepare_semantic_fragment_root_publication,
    snapshot_semantic_fragment_inputs,
    realize_semantic_patch_plan,
)
from d810.hexrays.mutation.semantic_fragment_profile import (
    SemanticFragmentPublicationProfile,
)
from d810.hexrays.mutation.semantic_fragment_inventory import (
    SemanticFragmentRootInventory,
)
from d810.hexrays.mutation.semantic_fragment_preparation import (
    PreparedSemanticFragment,
    sdk_owned_call,
)
from d810.hexrays.mutation.terminal_return_lifecycle import (
    protect_scalar_return_register,
)
from d810.hexrays.mutation.cfg_verify import capture_failure_artifact
from d810.hexrays.mutation.cfg_verify import register_resolver_proven_live_predicate
from d810.hexrays.mutation.cfg_mutations import CPBLK_MINREF, copy_block_keep
from d810.hexrays.mutation.cfg_mutations import change_0way_block_successor
from d810.hexrays.mutation.cfg_mutations import change_1way_block_successor
from d810.hexrays.mutation.cfg_mutations import change_2way_block_conditional_successor
from d810.hexrays.mutation.cfg_mutations import (
    canonicalize_explicit_return_to_stop_edge as _canonicalize_return_to_stop_edge,
)
from d810.hexrays.mutation.cfg_mutations import coalesce_jtbl_cases
from d810.transforms.cfg_transaction import PlanBlockRef, TransactionAttemptId
from d810.hexrays.mutation.cfg_mutations import create_standalone_block
from d810.hexrays.mutation.cfg_mutations import downgrade_nway_null_tail_to_1way
from d810.hexrays.mutation.cfg_mutations import duplicate_block
from d810.hexrays.mutation.cfg_mutations import ensure_child_has_an_unconditional_father
from d810.hexrays.mutation.cfg_mutations import ensure_last_block_is_goto
from d810.hexrays.mutation.cfg_mutations import insert_nop_blk
from d810.hexrays.mutation.cfg_mutations import _get_fallthrough_successor_serial
from d810.hexrays.mutation.cfg_mutations import insert_goto_instruction
from d810.hexrays.mutation.cfg_mutations import retarget_jtbl_block_cases
from d810.hexrays.mutation.cfg_verify import log_block_info
from d810.hexrays.mutation.cfg_mutations import make_2way_block_goto
from d810.hexrays.mutation.cfg_mutations import mba_deep_cleaning
from d810.hexrays.mutation.cfg_verify import safe_verify
from d810.hexrays.mutation.cfg_verify import snapshot_block_for_capture
from d810.hexrays.mutation.cfg_mutations import remove_block_edge
from d810.hexrays.mutation.cfg_mutations import _rewire_edge
from d810.ir.flowgraph import FlowGraph, InsnSnapshot
from d810.hexrays.mutation.insn_snapshot_materializer import (
    materialize_insn_snapshots,
)
from d810.hexrays.opcode_lift import opcode_name
from d810.hexrays.ir.block_helpers import get_pred_serials, get_succ_serials
from d810.hexrays.ir.semantic_edge import (
    LogicalSemanticEdge,
    LogicalSemanticEdgeOperation,
    SemanticEdgeOperationRejected,
)
from d810.hexrays.ir.logical_block_proxy import LogicalBlockVersion
from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.hexrays.mutation.ir_translator import lift
from d810.ir.block_identity import (
    BlockHandleProvenance,
    CurrentMbaBlockIdentityBinding,
    CurrentMbaIdentityBindingSnapshot,
    MbaBlockHandle,
    StableBlockIdentity,
)
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.transforms.fragment_plan import FragmentPlan

if TYPE_CHECKING:
    pass

logger = getLogger("d810.deferred_modifier")

_MAX_CAPTURE_HISTORY = 12


def _is_redirectable_conditional_tail(tail: object | None) -> bool:
    """Return true when ``tail.d.b`` is the conditional/taken edge."""
    if tail is None:
        return False
    return int(tail.opcode) in {
        int(ida_hexrays.m_jcnd),
        int(ida_hexrays.m_jnz),
        int(ida_hexrays.m_jz),
        int(ida_hexrays.m_jae),
        int(ida_hexrays.m_jb),
        int(ida_hexrays.m_ja),
        int(ida_hexrays.m_jbe),
        int(ida_hexrays.m_jg),
        int(ida_hexrays.m_jge),
        int(ida_hexrays.m_jl),
        int(ida_hexrays.m_jle),
    }


def canonicalize_explicit_return_to_stop_edge(
    block: ida_hexrays.mblock_t,
    stop: ida_hexrays.mblock_t,
) -> bool:
    """Execute canonical return-edge mutation through the backend boundary."""
    return _canonicalize_return_to_stop_edge(block, stop)


def invalidate_use_def_after_type_refinement(mba: ida_hexrays.mba_t) -> None:
    """Invalidate live use/def lists after changing the transient prototype."""
    for serial in range(int(getattr(mba, "qty", 0) or 0)):
        block = mba.get_mblock(serial)
        if block is not None:
            block.mark_lists_dirty()
    mba.mark_chains_dirty()


def refine_transient_terminal_return_type(
    mba: object,
    return_widths: Collection[int],
) -> bool:
    """Refine a guessed void MBA type from planned ABI return assignments."""
    carrier_widths = {int(width) for width in return_widths}
    if len(carrier_widths) != 1:
        return False
    carrier_width = next(iter(carrier_widths))
    integer_base_types = {
        1: int(ida_typeinf.BT_INT8),
        2: int(ida_typeinf.BT_INT16),
        4: int(ida_typeinf.BT_INT32),
        8: int(ida_typeinf.BT_INT64),
    }
    base_type = integer_base_types.get(carrier_width)
    function_type = getattr(mba, "idb_type", None)
    is_function = getattr(function_type, "is_func", None)
    if base_type is None or not callable(is_function) or not is_function():
        return False
    current_return_type = function_type.get_rettype()
    if not current_return_type.is_void():
        if int(current_return_type.get_size()) != carrier_width:
            return False
        protected = protect_scalar_return_register(mba, carrier_width)
        if not bool(mba.final_type):
            mba.clr_mba_flags(ida_hexrays.MBA_REFINE)
        return protected
    if bool(mba.final_type):
        return False
    return_type = ida_typeinf.tinfo_t(int(base_type) | int(ida_typeinf.BTMT_UNKSIGN))
    if int(return_type.get_size()) != carrier_width:
        return False
    get_cc = getattr(function_type, "get_cc", None)
    current_cc = int(get_cc()) if callable(get_cc) else None
    if current_cc == int(ida_typeinf.CM_CC_UNKNOWN):
        function_details = ida_typeinf.func_type_data_t()
        if not function_type.get_func_details(function_details):
            return False
        function_details.rettype = return_type
        function_details.flags = int(function_details.flags) & ~int(
            ida_typeinf.FTI_NORET
        )
        function_details.set_cc(ida_ida.inf_get_callcnv())
        refined_function_type = ida_typeinf.tinfo_t()
        if not refined_function_type.create_func(function_details):
            return False
    else:
        if int(function_type.set_func_rettype(return_type)) != int(
            ida_typeinf.TERR_OK
        ):
            return False
        refined_function_type = function_type
    mba.idb_type = refined_function_type
    mba.clr_mba_flags(ida_hexrays.MBA_REFINE)
    protect_scalar_return_register(mba, carrier_width)
    # A return has no explicit microcode operand: Hex-Rays derives its implicit
    # ABI-register use from ``mba.idb_type`` while building block use/def lists.
    invalidate_use_def_after_type_refinement(mba)
    return True


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
        part
        for part in (
            os.environ.get("D810_DEFERRED_WATCH_EDGE", ""),
            os.environ.get("D810_DEFERRED_WATCH_EDGES", ""),
        )
        if part
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

    def _safe_int_attr(obj, name: str):
        with contextlib.suppress(Exception):
            return int(getattr(obj, name))
        return None

    def _safe_edge_list(obj, attr_name: str) -> list[int] | str:
        try:
            raw = getattr(obj, attr_name, None)
            if raw is not None:
                return [int(x) for x in raw]
        except Exception as exc:
            return f"<{attr_name}-error:{type(exc).__name__}:{exc}>"
        return []

    serial = _safe_int_attr(blk, "serial")
    blk_type_value = _safe_int_attr(blk, "type")
    blk_type_names = {
        ida_hexrays.BLT_NONE: "NONE",
        ida_hexrays.BLT_STOP: "STOP",
        ida_hexrays.BLT_0WAY: "0WAY",
        ida_hexrays.BLT_1WAY: "1WAY",
        ida_hexrays.BLT_2WAY: "2WAY",
        ida_hexrays.BLT_NWAY: "NWAY",
        ida_hexrays.BLT_XTRN: "XTRN",
    }
    if blk_type_value is None:
        blk_type = "UNK(?)"
    else:
        blk_type = blk_type_names.get(blk_type_value, f"UNK({blk_type_value})")

    succs = _safe_edge_list(blk, "succset")
    preds = _safe_edge_list(blk, "predset")
    succ_str = f"succs={succs}"
    pred_str = f"preds={preds}"

    tail = None
    with contextlib.suppress(Exception):
        tail = blk.tail
    tail_str = "tail=None"
    if tail is not None:
        opcode = _safe_int_attr(tail, "opcode")
        ea = _safe_int_attr(tail, "ea")
        ea_str = hex(ea) if ea is not None else "?"
        tail_str = (
            f"tail.opcode={opcode if opcode is not None else '?'} tail.ea={ea_str}"
        )

    serial_str = serial if serial is not None else "?"
    return f"blk[{serial_str}] type={blk_type} {succ_str} {pred_str} {tail_str}"


def _mlist_dstr(value) -> str | None:
    if value is None:
        return None
    dstr = getattr(value, "dstr", None)
    if dstr is None:
        return None
    try:
        text = dstr()
    except Exception:
        return None
    return text or None


_LOCAL_VAR_TOKEN_RE = re.compile(r"(?:%var_[0-9A-Fa-f]+|v\d+)")


def _canonical_local_var_token(token: str | None) -> str | None:
    if token is None:
        return None
    if token.startswith("%var_"):
        return f"%var_{token[5:].upper()}"
    return token


def _mop_text(mop: object | None) -> str:
    if mop is None:
        return ""
    dstr = getattr(mop, "dstr", None)
    if callable(dstr):
        try:
            return str(dstr())
        except Exception:
            pass
    return str(mop)


def _insn_text(insn: object | None) -> str:
    if insn is None:
        return ""
    dstr = getattr(insn, "dstr", None)
    if callable(dstr):
        try:
            return str(dstr())
        except Exception:
            pass
    return str(insn)


def _instruction_text_digest(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", errors="replace")).hexdigest()[:16]


def _mop_local_var_token(mop: object | None) -> str | None:
    tokens = tuple(
        _canonical_local_var_token(match.group(0))
        for match in _LOCAL_VAR_TOKEN_RE.finditer(_mop_text(mop))
    )
    tokens = tuple(token for token in tokens if token is not None)
    return tokens[-1] if tokens else None


def _copy_mop_for_alias_scalarization(mop: object | None) -> object | None:
    if mop is None:
        return None
    try:
        copied = ida_hexrays.mop_t()
        copied.assign(mop)
        return copied
    except Exception:
        return None


def _apply_alias_scalarization_size_hint(
    mop: object | None,
    size_hint: int | None,
) -> object | None:
    if mop is None:
        return None
    try:
        hint = int(size_hint or 0)
    except Exception:
        hint = 0
    if hint > 0:
        with contextlib.suppress(Exception):
            mop.size = hint
    return mop


def _trace_conditional_redirect_step(
    label: str,
    mba: ida_hexrays.mba_t,
    *,
    blocks: tuple[ida_hexrays.mblock_t | None, ...],
) -> None:
    if not (
        _env_flag("D810_TRACE_CONDITIONAL_REDIRECT") or _env_flag("D810_DEBUG_LOGGING")
    ):
        return

    logger.warning("COND-REDIRECT TRACE %s", label)
    for blk in blocks:
        if blk is None:
            continue
        logger.warning("  %s", _format_block_info(blk))
        for attr in ("mustbuse", "maybuse", "mustbdef", "maybdef", "dnu"):
            text = _mlist_dstr(getattr(blk, attr, None))
            if text:
                logger.warning("    %s=%s", attr, text)
    try:
        mba.verify(True)
    except Exception as exc:
        logger.warning("  verify=%s: %s", type(exc).__name__, exc)
    else:
        logger.warning("  verify=ok")


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


def _is_live_block_serial(mba: ida_hexrays.mba_t, serial: int | None) -> bool:
    """Return whether *serial* is currently addressable in *mba*."""
    if serial is None:
        return False
    try:
        serial_i = int(serial)
        return 0 <= serial_i < int(mba.qty)
    except Exception:
        return False


class ModificationType(Enum):
    """Types of graph modifications that can be queued."""

    BLOCK_GOTO_CHANGE = auto()  # Change goto destination
    BLOCK_TARGET_CHANGE = auto()  # Change conditional jump target
    BLOCK_FALLTHROUGH_CHANGE = auto()  # Change fallthrough successor
    BLOCK_TERMINAL_GOTO_CHANGE = auto()  # Convert 0-way block to 1-way goto
    BLOCK_CONVERT_TO_GOTO = auto()  # Convert 2-way to 1-way block
    BLOCK_NWAY_NULL_TAIL_DOWNGRADE = (
        auto()
    )  # Downgrade degenerate NWAY null-tail to 1-way
    BLOCK_NWAY_GOTO_TYPE_DOWNGRADE = auto()  # Downgrade NWAY+m_goto+1succ to 1-way
    BLOCK_NOP_INSNS = auto()  # NOP instructions in a block
    INSN_REMOVE = auto()  # Remove a specific instruction
    INSN_NOP = auto()  # NOP a specific instruction
    INSN_CONST_MOV_AND_NOP_PAIR = (
        auto()
    )  # Replace one body insn with const mov and NOP another
    INSN_ZERO_STATE_WRITE = auto()  # Zero source operand of state variable write
    INSN_PROMOTE_OPERAND_TO_SCALAR = (
        auto()
    )  # Hoist a fused mop_d sub-instruction to a fresh kreg
    INSN_SCALARIZE_LOCAL_ALIAS_ACCESS = (
        auto()
    )  # Rewrite proven local pointer alias ldx/stx through its base local
    INSN_RETARGET_OUTPUT_STORE = (
        auto()
    )  # Rewrite a proven output-store address to the output pointer carrier
    MATERIALIZE_ZERO_WAY_CONDITIONAL = (
        auto()
    )  # Preserve a generated m_jcnd and bind its two proven CFG arms
    MATERIALIZE_ZERO_WAY_GOTO = (
        auto()
    )  # Replace one proven generated m_jcnd with its direct route
    LOWER_CONDITIONAL_STATE_TRANSITION = (
        auto()
    )  # Replace state-write-to-dispatcher with a proven 2-way edge
    NORMALIZE_NWAY_DISPATCHER_EXIT = (
        auto()
    )  # Downgrade degenerate NWAY dispatcher exit to 1-way
    BYPASS_DISPATCHER_TRAMPOLINE = (
        auto()
    )  # Redirect an edge away from a dispatcher trampoline
    CANONICALIZE_JTBL_CASE_OVERLAP = (
        auto()
    )  # Retarget/coalesce jump-table overlap cases
    PHASE_CYCLE_LOWERING = auto()  # Lower dispatcher phase-cycle entry redirects
    BLOCK_CREATE_WITH_REDIRECT = auto()  # Create intermediate block and redirect
    BLOCK_CREATE_WITH_CONDITIONAL_REDIRECT = (
        auto()
    )  # Create conditional 2-way block with redirect
    BLOCK_DUPLICATE_AND_REDIRECT = (
        auto()
    )  # Duplicate source block and redirect one predecessor
    BLOCK_DUPLICATE_REPLAY_AND_REDIRECT = (
        auto()
    )  # Per-pred duplicate + replay insert + redirect
    CLONE_CONDITIONAL_AS_GOTO = (
        auto()
    )  # Clone 2-way conditional, convert clone to goto, redirect predecessor
    CLONE_CONDITIONAL_AS_GOTO_FROM_BRANCH_ARM = (
        auto()
    )  # 2-way predecessor branch-arm sibling of CLONE_CONDITIONAL_AS_GOTO
    EDGE_REDIRECT_VIA_PRED_SPLIT = (
        auto()
    )  # Clone src block; redirect one predecessor to clone
    EDGE_SPLIT_TRAMPOLINE = (
        auto()
    )  # Materialize standalone trampoline and redirect one predecessor
    EDGE_REMOVE = auto()  # Remove a single edge (2-way→1-way or 1-way→0-way)
    PRIVATE_TERMINAL_SUFFIX = auto()  # Clone shared suffix chain per anchor
    PRIVATE_TERMINAL_SUFFIX_GROUP = (
        auto()
    )  # Clone shared suffix chain for multiple anchors atomically
    DIRECT_TERMINAL_LOWERING_GROUP = (
        auto()
    )  # Direct terminal lowering for multiple anchors
    REORDER_BLOCKS = auto()  # Copy handler blocks in DFS order to end of MBA


class TargetRefKind(Enum):
    """How a modification target should be interpreted at apply-time."""

    ABSOLUTE = auto()
    STOP_BLOCK = auto()  # Resolve to current mba.qty - 1 at apply-time


class StagedAtomicClassification(Enum):
    """Classification of a queued modification for the ``staged_atomic`` apply path.

    The ``apply(staged_atomic=True)`` mode gives real atomicity: the
    intermediate state where the new copy exists but predecessors are not yet
    rewired is invisible to any external observer of the MBA.  To accomplish
    this, each queued modification must be classified into one of the buckets
    below; each bucket takes a different path through the four-phase
    orchestration (classify → stage → commit → cleanup).

    Buckets:

    * ``ADDITIVE``        -- The modification only creates new ``mblock_t``
      objects (via ``mba.copy_block``/``create_standalone_block``) and, at
      most, rewires the *one* predecessor it logically owns.  It never
      destroys pre-existing block topology until the tail redirect step,
      which itself is guarded and can fail cleanly.  Existing handlers such
      as ``PrivateTerminalSuffixGroup`` and ``ExitPathLoweringGroup``
      already follow this pattern.  Apply these directly through the normal
      ``_apply_single`` dispatcher during the commit phase.

    * ``DESTRUCTIVE_EXPRESSIBLE`` -- The modification currently mutates an
      existing block's tail / succset / predset in-place.  Under
      ``staged_atomic`` these are lowered into a
      *copy-and-swap* sequence: ``mba.copy_block`` the target block,
      apply the intended mutation on the *copy*, record a pending rewire
      of every external predecessor to point at the copy, and defer both
      the redirect and the cleanup of the now-orphaned original block to
      the commit / cleanup phases.  Currently covers
      ``BLOCK_GOTO_CHANGE``, ``BLOCK_TARGET_CHANGE``,
      ``BLOCK_CONVERT_TO_GOTO``, and ``EDGE_REMOVE``.

    * ``INSTRUCTION_ONLY`` -- The modification touches instructions inside
      an existing block but never changes the block's topology (succset /
      predset / type).  These are always safe to apply after the
      staging / commit / cleanup phases have settled the CFG shape.
      Covers ``INSN_REMOVE``, ``INSN_NOP``, ``INSN_ZERO_STATE_WRITE``,
      and ``BLOCK_NOP_INSNS``.

    * ``UNSUPPORTED`` -- The modification type has no staged_atomic
      lowering yet.  When encountered, the staged_atomic path falls back
      to the default sequential ``_apply_single`` behaviour for that mod
      (and logs a warning).  This is intentional: new mod types can be
      added without forcing a simultaneous update to the staged path.

    Reference template: ``_apply_private_terminal_suffix_group`` in this
    file -- it demonstrates the full
    ``validate -> snapshot -> copy -> wire -> redirect -> cleanup``
    sequence that the staged_atomic path generalises for the destructive
    bucket.
    """

    ADDITIVE = auto()
    DESTRUCTIVE_EXPRESSIBLE = auto()
    INSTRUCTION_ONLY = auto()
    UNSUPPORTED = auto()


# Mapping from ModificationType -> StagedAtomicClassification.  Kept as a
# module-level constant so classification is O(1) and can be introspected
# from unit tests without instantiating a modifier.  New modification types
# must be added here (or they default to UNSUPPORTED).
_STAGED_ATOMIC_CLASS_MAP: "dict[ModificationType, StagedAtomicClassification]" = {
    # Instruction-only: never touches block topology.
    ModificationType.INSN_REMOVE: StagedAtomicClassification.INSTRUCTION_ONLY,
    ModificationType.INSN_NOP: StagedAtomicClassification.INSTRUCTION_ONLY,
    ModificationType.INSN_CONST_MOV_AND_NOP_PAIR: StagedAtomicClassification.INSTRUCTION_ONLY,
    ModificationType.INSN_ZERO_STATE_WRITE: StagedAtomicClassification.INSTRUCTION_ONLY,
    ModificationType.INSN_PROMOTE_OPERAND_TO_SCALAR: StagedAtomicClassification.INSTRUCTION_ONLY,
    ModificationType.INSN_SCALARIZE_LOCAL_ALIAS_ACCESS: StagedAtomicClassification.INSTRUCTION_ONLY,
    ModificationType.INSN_RETARGET_OUTPUT_STORE: StagedAtomicClassification.INSTRUCTION_ONLY,
    ModificationType.BLOCK_NOP_INSNS: StagedAtomicClassification.INSTRUCTION_ONLY,
    # Destructive-expressible: mutate an existing block's tail/succset in-place.
    # Lowered to copy-and-swap under staged_atomic.
    ModificationType.BLOCK_GOTO_CHANGE: StagedAtomicClassification.DESTRUCTIVE_EXPRESSIBLE,
    ModificationType.BLOCK_TARGET_CHANGE: StagedAtomicClassification.DESTRUCTIVE_EXPRESSIBLE,
    ModificationType.BLOCK_TERMINAL_GOTO_CHANGE: StagedAtomicClassification.DESTRUCTIVE_EXPRESSIBLE,
    ModificationType.BLOCK_CONVERT_TO_GOTO: StagedAtomicClassification.DESTRUCTIVE_EXPRESSIBLE,
    ModificationType.EDGE_REMOVE: StagedAtomicClassification.DESTRUCTIVE_EXPRESSIBLE,
    ModificationType.MATERIALIZE_ZERO_WAY_CONDITIONAL: StagedAtomicClassification.DESTRUCTIVE_EXPRESSIBLE,
    ModificationType.MATERIALIZE_ZERO_WAY_GOTO: StagedAtomicClassification.DESTRUCTIVE_EXPRESSIBLE,
    ModificationType.LOWER_CONDITIONAL_STATE_TRANSITION: StagedAtomicClassification.DESTRUCTIVE_EXPRESSIBLE,
    # Additive: already create new blocks and defer the tail redirect.
    # Safe to apply through the default dispatcher during commit.
    ModificationType.BLOCK_CREATE_WITH_REDIRECT: StagedAtomicClassification.ADDITIVE,
    ModificationType.BLOCK_CREATE_WITH_CONDITIONAL_REDIRECT: StagedAtomicClassification.ADDITIVE,
    ModificationType.BLOCK_DUPLICATE_AND_REDIRECT: StagedAtomicClassification.ADDITIVE,
    ModificationType.CLONE_CONDITIONAL_AS_GOTO: StagedAtomicClassification.ADDITIVE,
    ModificationType.CLONE_CONDITIONAL_AS_GOTO_FROM_BRANCH_ARM: StagedAtomicClassification.ADDITIVE,
    ModificationType.EDGE_REDIRECT_VIA_PRED_SPLIT: StagedAtomicClassification.ADDITIVE,
    ModificationType.EDGE_SPLIT_TRAMPOLINE: StagedAtomicClassification.ADDITIVE,
    ModificationType.PRIVATE_TERMINAL_SUFFIX: StagedAtomicClassification.ADDITIVE,
    ModificationType.PRIVATE_TERMINAL_SUFFIX_GROUP: StagedAtomicClassification.ADDITIVE,
    ModificationType.DIRECT_TERMINAL_LOWERING_GROUP: StagedAtomicClassification.ADDITIVE,
    ModificationType.REORDER_BLOCKS: StagedAtomicClassification.ADDITIVE,
    # BLOCK_FALLTHROUGH_CHANGE: not currently emitted anywhere — mark UNSUPPORTED
    # so staged_atomic falls back to sequential apply if it ever shows up.
    ModificationType.BLOCK_FALLTHROUGH_CHANGE: StagedAtomicClassification.UNSUPPORTED,
    ModificationType.NORMALIZE_NWAY_DISPATCHER_EXIT: StagedAtomicClassification.UNSUPPORTED,
    ModificationType.BYPASS_DISPATCHER_TRAMPOLINE: StagedAtomicClassification.UNSUPPORTED,
    ModificationType.CANONICALIZE_JTBL_CASE_OVERLAP: StagedAtomicClassification.UNSUPPORTED,
    ModificationType.PHASE_CYCLE_LOWERING: StagedAtomicClassification.UNSUPPORTED,
}


def classify_for_staged_atomic(
    mod_type: "ModificationType",
) -> StagedAtomicClassification:
    """Return the staged_atomic classification for a given modification type.

    Exposed at module level so tests and planners can reason about
    classifications without instantiating a modifier.
    """
    return _STAGED_ATOMIC_CLASS_MAP.get(
        mod_type, StagedAtomicClassification.UNSUPPORTED
    )


def _get_mblock_by_start_ea(
    mba: "ida_hexrays.mba_t",
    start_ea: int,
) -> "ida_hexrays.mblock_t | None":
    """Return the block in ``mba`` whose ``start`` address matches ``start_ea``.

    Bug 3 fix helper — block *serials* are positional indexes that shift
    whenever ``mba.insert_block``/``mba.copy_block``/``mba.remove_block``
    touches the block array, while ``mblock_t.start`` (byte-address range
    start) is stable across those mutations.  The staged_atomic pipeline
    captures start EAs at staging time and re-resolves blocks via this
    helper at every phase boundary (commit, cleanup) so a stale positional
    index is never used as a handle.

    Returns ``None`` if no block matches (e.g. the block was removed
    out-of-band between phases).  Iteration is O(mba.qty); cheap enough
    for our workloads and we deliberately do not cache across phases
    because block shifts between phases would invalidate a serial cache.
    """
    if mba is None or start_ea is None:
        return None
    try:
        qty = int(mba.qty)
    except Exception:
        return None
    for serial in range(qty):
        try:
            blk = mba.get_mblock(serial)
        except Exception:
            continue
        if blk is None:
            continue
        try:
            if int(blk.start) == int(start_ea):
                return blk
        except Exception:
            continue
    return None


def _audit_special_block_instructions(
    mba: "ida_hexrays.mba_t",
    *,
    phase: str,
) -> list[dict[str, object]]:
    """Report CFG_51814 offenders: non-empty blocks in special slots/types.

    IDA's ``verify.cpp:1055-1058`` enforces that entry (serial==0),
    exit (type==BLT_STOP), and extern (type==BLT_XTRN) blocks have
    ``head == nullptr`` — *i.e.* no instructions.  Any non-empty block
    in one of these positions/types triggers ``MBLOCK_INTERR(51814)``
    before our ``safe_verify`` call can recover.

    This helper walks all blocks in ``mba`` and returns a record for
    every offender.  Intended to run right before ``safe_verify`` in
    mutation pipelines so the exact offending block(s) are logged with
    full provenance (serial, type, start/tail EA, succs/preds, head
    opcode) rather than a bare ``INTERR 51814``.  Always on — the walk
    is O(mba.qty) and only logs when something is wrong.
    """
    offenders: list[dict[str, object]] = []
    if mba is None:
        return offenders
    try:
        qty = int(mba.qty)
    except Exception:
        return offenders
    blt_stop = ida_hexrays.BLT_STOP
    blt_xtrn = ida_hexrays.BLT_XTRN
    blk_type_names = {
        ida_hexrays.BLT_NONE: "NONE",
        ida_hexrays.BLT_STOP: "STOP",
        ida_hexrays.BLT_0WAY: "0WAY",
        ida_hexrays.BLT_1WAY: "1WAY",
        ida_hexrays.BLT_2WAY: "2WAY",
        ida_hexrays.BLT_NWAY: "NWAY",
        ida_hexrays.BLT_XTRN: "XTRN",
    }
    for serial in range(qty):
        try:
            blk = mba.get_mblock(serial)
        except Exception:
            continue
        if blk is None:
            continue
        try:
            blk_type = int(blk.type)
        except Exception:
            continue
        is_special_serial = serial == 0
        is_special_type = blk_type in (blt_stop, blt_xtrn)
        if not (is_special_serial or is_special_type):
            continue
        try:
            head = blk.head
        except Exception:
            head = None
        if head is None:
            continue  # empty → legal
        # Non-empty special block → CFG_51814 offender.
        try:
            tail = blk.tail
        except Exception:
            tail = None
        if is_special_type:
            reason = "exit_type_STOP" if blk_type == blt_stop else "extern_type_XTRN"
        else:
            reason = "entry_serial_0"
        offender = {
            "phase": phase,
            "serial": serial,
            "type": blk_type,
            "type_name": blk_type_names.get(blk_type, f"UNK({blk_type})"),
            "start_ea": int(getattr(blk, "start", 0) or 0),
            "head_ea": int(getattr(head, "ea", 0) or 0),
            "head_opcode": int(getattr(head, "opcode", 0) or 0),
            "tail_ea": int(getattr(tail, "ea", 0) or 0) if tail else None,
            "tail_opcode": int(getattr(tail, "opcode", 0) or 0) if tail else None,
            "succs": [int(blk.succset[k]) for k in range(blk.succset.size())],
            "preds": [int(blk.predset[k]) for k in range(blk.predset.size())],
            "reason": reason,
        }
        offenders.append(offender)
        logger.error(
            "CFG_51814_OFFENDER[%s]: blk[%d] type=%s start=0x%x head.ea=0x%x "
            "tail.ea=%s succs=%s preds=%s reason=%s",
            phase,
            serial,
            offender["type_name"],
            offender["start_ea"],
            offender["head_ea"],
            "0x%x" % offender["tail_ea"] if offender["tail_ea"] else "None",
            offender["succs"],
            offender["preds"],
            offender["reason"],
        )
    return offenders


@dataclass
class _StagedPendingRewire:
    """Record of a pending predecessor rewire produced during the staging phase.

    The staging phase copies the destructive-expressible mod's target block,
    applies the intended mutation to the copy, and records one of these to
    redirect external predecessors at commit time.

    Bug 4 fix — mblock_t pointer identity
    -------------------------------------
    Earlier revisions used ``original_start_ea`` / ``new_start_ea`` as
    the stable identity key and re-resolved via ``_get_mblock_by_start_ea``
    at each phase boundary.  That worked for the Bug 3 serial-drift case
    but *silently fails* in the presence of ``mba.copy_block``: the IDA
    SDK copies the source block's ``start`` address onto the clone, so
    original and copy share the same start EA.  ``_get_mblock_by_start_ea``
    iterates ``range(mba.qty)`` and returns the first match — always the
    lower-numbered original — so every lookup of the copy's EA incorrectly
    returns the original.  ``_commit_staged_rewire`` then rewired preds to
    the original block (no-op), leaving the copy orphaned and the CFG
    semantically broken (observed on sub_7FFD: ``while(1);`` collapse).

    mblock_t pointers are stable across ``insert_block`` / ``copy_block``
    (those operations never reallocate existing block objects) and remain
    valid until an explicit ``remove_block`` on that specific block.  For
    staged_atomic's purposes — where we only remove originals at the very
    end of Phase 4 — holding direct pointers for originals, copies, and
    preds is the correct identity.

    Fields:
        original_blk: mblock_t pointer to the pre-existing block being
            logically replaced.  Stable across Phase 2-3 mutations; may
            become invalid after Phase 4 ``remove_block``.
        new_blk: mblock_t pointer to the freshly-copied block.  Stable
            throughout the pipeline (we never remove copies).
        preds_to_redirect: Tuple of mblock_t pointers to external
            predecessors captured at staging time.  Stable across
            subsequent stages.
        mod_type: The original ModificationType (retained for
            diagnostics and to pick the correct wiring helper at commit).
        original_serial: Snapshot of the original's serial at staging
            time (diagnostics only — use ``original_blk.serial`` for live).
        new_serial: Snapshot of the copy's serial at staging time
            (diagnostics only — use ``new_blk.serial`` for live).
        original_start_ea: Snapshot of the original's start EA at
            staging time (diagnostics only; not a reliable identity).
        new_start_ea: Snapshot of the copy's start EA at staging time
            (diagnostics only; equals original_start_ea in practice).
    """

    original_blk: "ida_hexrays.mblock_t"
    new_blk: "ida_hexrays.mblock_t"
    preds_to_redirect: tuple["ida_hexrays.mblock_t", ...]
    mod_type: "ModificationType"
    original_serial: int = -1
    new_serial: int = -1
    original_start_ea: int = -1
    new_start_ea: int = -1


@dataclass(frozen=True)
class _SyntheticRegisterComparisonCondition:
    """Backend-only description of one direct register comparison branch."""

    branch_opcode: int
    predicate_register: int
    predicate_size: int
    predicate_constant: int


@dataclass
class QueuedModification:
    """Represents a single queued graph modification."""

    mod_type: ModificationType
    block_serial: int
    # Target for goto/jump changes
    new_target: int | None = None
    # For instruction-level operations
    insn_ea: int | None = None
    # For instruction-level operations that address payload-body ordinals
    insn_body_index: int | None = None
    secondary_insn_body_index: int | None = None
    const_value: int | None = None
    replacement_dest: object | None = None
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
    # For CLONE_CONDITIONAL_AS_GOTO_FROM_BRANCH_ARM: predecessor arm to rewire
    pred_arm: int | None = None
    # For EDGE_REDIRECT_VIA_PRED_SPLIT: future corridor cloning endpoint (unused, stub)
    clone_until: int | None = None
    # For EDGE_REDIRECT_VIA_PRED_SPLIT corridor: optional target for original source
    source_new_target: int | None = None
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
    # For BLOCK_DUPLICATE_AND_REDIRECT: also redirect the original block's successor
    original_redirect_target: int | None = None
    # For BLOCK_DUPLICATE_REPLAY_AND_REDIRECT:
    # (pred, target, expected_replay_serial, expected_clone_serial, instructions)
    replay_entries: tuple | None = None
    # For REORDER_BLOCKS: ordered block serials to copy in DFS order
    dfs_block_order: tuple[int, ...] | None = None
    # For REORDER_BLOCKS: pre-computed old_serial -> new_serial mapping from PatchPlan
    old_to_new: dict[int, int] | None = None
    # For REORDER_BLOCKS: pre-computed old_serial -> trampoline_serial for 2WAY blocks
    old_to_trampoline: dict[int, int] | None = None
    # For INSN_PROMOTE_OPERAND_TO_SCALAR: opcode of the host instruction
    host_opcode: int | None = None
    # For INSN_PROMOTE_OPERAND_TO_SCALAR: which operand side to extract ("l" | "r")
    operand_side: str | None = None
    # For INSN_SCALARIZE_LOCAL_ALIAS_ACCESS: local pointer alias and base local tokens
    alias_token: str | None = None
    base_token: str | None = None
    host_text_sha1: str | None = None
    value_size: int | None = None
    # For LOWER_CONDITIONAL_STATE_TRANSITION
    rewrite_from_ea: int | None = None
    condition_operand: object | None = None
    false_target: int | None = None
    true_target: int | None = None
    proof_id: str | None = None
    state_register: int | None = None
    state_size: int | None = None
    false_state: int | None = None
    true_state: int | None = None
    false_state_write_ea: int | None = None
    true_state_write_ea: int | None = None
    # For NORMALIZE_NWAY_DISPATCHER_EXIT
    dispatcher_entry_serial: int | None = None
    keep_target_serial: int | None = None
    # For CANONICALIZE_JTBL_CASE_OVERLAP
    retarget_map: tuple[tuple[int, int], ...] | None = None
    deduplicate_cases: bool = False
    # For PHASE_CYCLE_LOWERING
    phase_header_entries: tuple[int, ...] | None = None
    phase_header_target: int | None = None
    phase_body_entries: tuple[int, ...] | None = None
    phase_body_target: int | None = None
    phase_next_phase_entries: tuple[int, ...] | None = None
    phase_next_phase_target: int | None = None
    phase_terminal_entries: tuple[int, ...] | None = None
    phase_terminal_target: int | None = None


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
        raise TypeError(
            "Mixed symbolic/live instructions_to_copy payload is unsupported"
        )

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

        class MyOptimizer(FlowOptimizationRule):
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
    modifications: list[QueuedModification] = field(default_factory=list)
    _applied: bool = False
    verify_failed: bool = False
    transaction_complete: bool = False
    last_apply_phase: str | None = None
    last_apply_subphase: str | None = None
    last_stale_serial_scan: dict | None = None
    _pre_snapshot: FlowGraph | None = None
    # Optional event emitter; when None, no events are emitted (zero overhead).
    event_emitter: EventEmitter | None = None
    # Session/manager-owned transaction gateway. Structural writes fail closed
    # when the coordinator has not injected this port.
    mutation_gateway: MbaMutationGateway | None = None
    # Backend-owned body importer used only inside semantic-fragment staging.
    semantic_native_body_materializer: SemanticNativeBodyMaterializer | None = None
    semantic_fragment_publication_profile: SemanticFragmentPublicationProfile = (
        SemanticFragmentPublicationProfile.CFG_READY
    )
    # Metadata injected by callers so payloads carry rich context.
    _optimizer_name: str = field(default="", init=False)
    _pass_id: int = field(default=0, init=False)
    _session_id: str = field(default="", init=False)
    # The receipt gateway owns current-MBA serial bindings.  This modifier
    # retains neither an EA-to-serial cache nor a private serial-remap table.
    _mutation_gateway: MbaMutationGateway | None = field(default=None, init=False)
    _semantic_native_body_materializer: SemanticNativeBodyMaterializer | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _semantic_fragment_state: SemanticFragmentBackendState | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _consumed_semantic_fragment_attempts: set[TransactionAttemptId] = field(
        default_factory=set,
        init=False,
        repr=False,
    )
    _pending_semantic_helper_version: LogicalBlockVersion | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _patch_plan_ref_by_bound_serial: dict[int, PlanBlockRef] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )
    _realized_patch_serial_by_bound_serial: dict[int, int] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        if not isinstance(
            self.semantic_fragment_publication_profile,
            SemanticFragmentPublicationProfile,
        ):
            raise TypeError(
                "DeferredGraphModifier requires a typed fragment publication profile"
            )
        self._mutation_gateway = self.mutation_gateway
        self._semantic_native_body_materializer = self.semantic_native_body_materializer

    def refine_transient_terminal_return_type_now(
        self,
        return_widths: Collection[int],
    ) -> bool:
        """Apply transient return-type refinement through this backend."""
        return refine_transient_terminal_return_type(self.mba, return_widths)

    def reset(self) -> None:
        """Clear all queued modifications."""
        self.modifications.clear()
        self._applied = False
        if self._mutation_gateway is not None:
            self._mutation_gateway.abort()
        self._mutation_gateway = self.mutation_gateway
        self._semantic_native_body_materializer = self.semantic_native_body_materializer
        self.last_apply_phase = None
        self.last_apply_subphase = None
        self.last_stale_serial_scan = None

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

    def configure_patch_bindings(self, bound_plan, *, mutation_gateway=None) -> None:
        """Install attempt-local creation ownership before queueing writes."""
        attempt = bound_plan.attempt_id
        gateway = mutation_gateway or self._mutation_gateway
        if gateway is None or not gateway.active:
            raise RuntimeError("patch binding requires an active mutation gateway")
        if gateway is not self._mutation_gateway:
            raise ValueError("patch binding gateway differs from modifier authority")
        if gateway.current_transaction_attempt != attempt:
            raise ValueError("patch binding attempt is not the active gateway attempt")
        self._patch_plan_ref_by_bound_serial = {
            int(bound_plan.serial_for(spec.block_id)): spec.block_id
            for spec in bound_plan.plan.new_blocks
        }
        self._realized_patch_serial_by_bound_serial.clear()

    def observe_live_graph(self):
        """Lift the post-apply MBA for transaction observation and commit."""
        return lift(self.mba)

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

    def _set_apply_phase(self, phase: str, subphase: str | None = None) -> None:
        self.last_apply_phase = phase
        self.last_apply_subphase = subphase

    def _maybe_scan_stale_block_refs(self, *, subphase: str) -> dict | None:
        if not (_env_flag("D810_DEFERRED_SCAN_STALE_SERIALS") or logger.debug_on):
            return None

        qty = int(self.mba.qty)
        issues: list[dict[str, object]] = []
        for serial in range(qty):
            blk = self.mba.get_mblock(serial)
            if blk is None:
                issues.append({"kind": "missing_block", "block_serial": serial})
                if len(issues) >= 8:
                    break
                continue

            succs = tuple(int(s) for s in get_succ_serials(blk))
            preds = tuple(int(p) for p in get_pred_serials(blk))
            for succ in succs:
                if succ < 0 or succ >= qty:
                    issues.append(
                        {
                            "kind": "succ",
                            "block_serial": serial,
                            "ref_serial": succ,
                        }
                    )
            for pred in preds:
                if pred < 0 or pred >= qty:
                    issues.append(
                        {
                            "kind": "pred",
                            "block_serial": serial,
                            "ref_serial": pred,
                        }
                    )

            # ``mblock_t.nextb`` / ``mblock_t.prevb`` return block POINTERS
            # (mblock_t), not serial integers.  ``int(mblock_t)`` raises
            # TypeError("int() argument must be ... not 'mblock_t'") and
            # propagates as a ``raw_apply`` failure at the engine's
            # backend_apply phase.  Read the linked block's ``.serial``
            # instead, defaulting to -1 when the link is None.
            _nextb_blk = getattr(blk, "nextb", None)
            nextb = (
                int(getattr(_nextb_blk, "serial", -1)) if _nextb_blk is not None else -1
            )
            if nextb >= qty:
                issues.append(
                    {
                        "kind": "nextb",
                        "block_serial": serial,
                        "ref_serial": nextb,
                    }
                )
            _prevb_blk = getattr(blk, "prevb", None)
            prevb = (
                int(getattr(_prevb_blk, "serial", -1)) if _prevb_blk is not None else -1
            )
            if prevb >= qty:
                issues.append(
                    {
                        "kind": "prevb",
                        "block_serial": serial,
                        "ref_serial": prevb,
                    }
                )

            tail = blk.tail
            if tail is not None and getattr(tail.d, "t", None) == ida_hexrays.mop_b:
                block_ref = int(tail.d.b)
                if block_ref < 0 or block_ref >= qty:
                    issues.append(
                        {
                            "kind": "tail_d_block_ref",
                            "block_serial": serial,
                            "ref_serial": block_ref,
                        }
                    )

            if len(issues) >= 8:
                break

        result = {"subphase": subphase, "qty": qty, "issues": tuple(issues)}
        self.last_stale_serial_scan = result
        if issues:
            logger.error(
                "STALE-SERIAL-SCAN subphase=%s qty=%d issues=%s",
                subphase,
                qty,
                issues,
            )
        else:
            logger.debug("STALE-SERIAL-SCAN subphase=%s clean qty=%d", subphase, qty)
        return result

    def _mod_payload(
        self, mod: QueuedModification, mod_index: int | None = None
    ) -> dict:
        """Extend a base payload with modification-specific fields."""
        payload = self._base_payload()
        payload.update(
            {
                "mod_index": mod_index,
                "mod_type": mod.mod_type.name,
                "block_serial": mod.block_serial,
                "new_target": mod.new_target,
                "target_ref_kind": mod.target_ref_kind.name,
                "priority": mod.priority,
                "rule_priority": mod.rule_priority,
                "pred_arm": mod.pred_arm,
                "description": mod.description,
            }
        )
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

    def _resolve_target_serial(self, mod: QueuedModification) -> int | None:
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

        ``BLOCK_GOTO_CHANGE`` is intentionally limited to 1-way blocks at
        apply time. Never use it to coerce a 2-way block into a goto: that
        drops one branch and corrupts the CFG. Use an explicit branch-target
        modification or a pred-split/clone primitive for conditional blocks.

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
        self.modifications.append(
            QueuedModification(
                mod_type=ModificationType.BLOCK_GOTO_CHANGE,
                block_serial=block_serial,
                new_target=new_target,
                priority=10,  # High priority - do block changes first
                description=description or f"goto {block_serial} -> {new_target}",
                rule_priority=rule_priority,
                target_ref_kind=resolved_target_kind,
            )
        )
        logger.debug(
            "Queued goto change: block %d -> %d (rule_priority=%d)",
            block_serial,
            new_target,
            rule_priority,
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
        old_target: int | None = None,
        expected_helper_serial: int | None = None,
        description: str = "",
        target_ref_kind: TargetRefKind | None = None,
    ) -> None:
        """Queue a change to a conditional jump's target."""
        resolved_target_kind = (
            target_ref_kind
            if target_ref_kind is not None
            else self._infer_target_ref_kind(new_target)
        )
        self.modifications.append(
            QueuedModification(
                mod_type=ModificationType.BLOCK_TARGET_CHANGE,
                block_serial=block_serial,
                new_target=new_target,
                old_target=old_target,
                expected_serial=expected_helper_serial,
                priority=10,
                description=description or f"jmp target {block_serial} -> {new_target}",
                target_ref_kind=resolved_target_kind,
            )
        )
        logger.debug(
            "Queued target change: block %d old_target=%s -> %d",
            block_serial,
            old_target,
            new_target,
        )
        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_QUEUE_ADDED,
                self._mod_payload(self.modifications[-1]),
            )

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
        self.modifications.append(
            QueuedModification(
                mod_type=ModificationType.BLOCK_CONVERT_TO_GOTO,
                block_serial=block_serial,
                new_target=goto_target,
                priority=20,  # After simple target changes
                description=description
                or f"convert {block_serial} to goto {goto_target}",
                target_ref_kind=resolved_target_kind,
            )
        )
        logger.debug(
            "Queued convert to goto: block %d -> %d", block_serial, goto_target
        )
        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_QUEUE_ADDED,
                self._mod_payload(self.modifications[-1]),
            )

    def queue_terminal_goto_change(
        self,
        block_serial: int,
        goto_target: int,
        description: str = "",
        target_ref_kind: TargetRefKind | None = None,
        priority: int = 20,
    ) -> None:
        """Queue conversion of a 0-way terminal block to a 1-way goto."""
        resolved_target_kind = (
            target_ref_kind
            if target_ref_kind is not None
            else self._infer_target_ref_kind(goto_target)
        )
        self.modifications.append(
            QueuedModification(
                mod_type=ModificationType.BLOCK_TERMINAL_GOTO_CHANGE,
                block_serial=block_serial,
                new_target=goto_target,
                priority=int(priority),
                description=description
                or f"terminal {block_serial} -> goto {goto_target}",
                target_ref_kind=resolved_target_kind,
            )
        )
        logger.debug(
            "Queued terminal goto change: block %d -> %d", block_serial, goto_target
        )
        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_QUEUE_ADDED,
                self._mod_payload(self.modifications[-1]),
            )

    def queue_nway_null_tail_downgrade(
        self,
        block_serial: int,
        dispatcher_entry_serial: int,
        description: str = "",
    ) -> None:
        """Queue downgrade of a degenerate BLT_NWAY/null-tail block to 1-way."""
        self.modifications.append(
            QueuedModification(
                mod_type=ModificationType.BLOCK_NWAY_NULL_TAIL_DOWNGRADE,
                block_serial=block_serial,
                dispatcher_entry_serial=dispatcher_entry_serial,
                priority=20,
                description=description
                or (
                    f"downgrade nway null-tail {block_serial}, "
                    f"drop {dispatcher_entry_serial}"
                ),
            )
        )
        logger.debug(
            "Queued nway null-tail downgrade: block %d drop %d",
            block_serial,
            dispatcher_entry_serial,
        )
        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_QUEUE_ADDED,
                self._mod_payload(self.modifications[-1]),
            )

    def queue_nway_goto_type_downgrade(
        self,
        block_serial: int,
        description: str = "",
    ) -> None:
        """Queue downgrade of BLT_NWAY+m_goto+single-successor to BLT_1WAY."""
        self.modifications.append(
            QueuedModification(
                mod_type=ModificationType.BLOCK_NWAY_GOTO_TYPE_DOWNGRADE,
                block_serial=block_serial,
                priority=20,
                description=description or f"downgrade nway goto {block_serial}",
            )
        )
        logger.debug("Queued nway goto type downgrade: block %d", block_serial)
        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_QUEUE_ADDED,
                self._mod_payload(self.modifications[-1]),
            )

    def queue_insn_remove(
        self,
        block_serial: int,
        insn_ea: int,
        description: str = "",
    ) -> None:
        """Queue removal of a specific instruction (by EA)."""
        self.modifications.append(
            QueuedModification(
                mod_type=ModificationType.INSN_REMOVE,
                block_serial=block_serial,
                insn_ea=insn_ea,
                priority=1000,  # Very low priority - do last
                description=description
                or f"remove insn at {hex(insn_ea)} in block {block_serial}",
            )
        )
        logger.debug("Queued insn remove: block %d, ea=%s", block_serial, hex(insn_ea))
        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_QUEUE_ADDED,
                self._mod_payload(self.modifications[-1]),
            )

    def queue_insn_nop(
        self,
        block_serial: int,
        insn_ea: int,
        description: str = "",
    ) -> None:
        """Queue NOP of a specific instruction (by EA)."""
        self.modifications.append(
            QueuedModification(
                mod_type=ModificationType.INSN_NOP,
                block_serial=block_serial,
                insn_ea=insn_ea,
                priority=900,  # Low priority but before removes
                description=description
                or f"nop insn at {hex(insn_ea)} in block {block_serial}",
            )
        )
        logger.debug("Queued insn nop: block %d, ea=%s", block_serial, hex(insn_ea))
        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_QUEUE_ADDED,
                self._mod_payload(self.modifications[-1]),
            )

    def queue_const_mov_and_nop_pair(
        self,
        block_serial: int,
        replacement_body_index: int,
        nop_body_index: int,
        const_value: int,
        replacement_dest: object,
        value_size: int | None = None,
        description: str = "",
    ) -> None:
        """Queue replacement of one payload instruction and NOP a paired one.

        Body indices are counted over non-NOP, non-goto instructions in the
        target block. This avoids relying on microcode EAs, which are often
        shared by several synthetic instructions in one block.
        """
        if replacement_body_index == nop_body_index:
            raise ValueError("replacement and NOP body indices must differ")
        self.modifications.append(
            QueuedModification(
                mod_type=ModificationType.INSN_CONST_MOV_AND_NOP_PAIR,
                block_serial=int(block_serial),
                insn_body_index=int(replacement_body_index),
                secondary_insn_body_index=int(nop_body_index),
                const_value=int(const_value),
                replacement_dest=replacement_dest,
                value_size=int(value_size or 0) or None,
                priority=900,
                description=description
                or (
                    f"replace body insn {replacement_body_index} with const mov "
                    f"and NOP body insn {nop_body_index} in block {block_serial}"
                ),
            )
        )
        logger.debug(
            "Queued const_mov_and_nop_pair: block %d replace=%d nop=%d",
            block_serial,
            replacement_body_index,
            nop_body_index,
        )
        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_QUEUE_ADDED,
                self._mod_payload(self.modifications[-1]),
            )

    def queue_zero_state_write(
        self,
        block_serial: int,
        insn_ea: int,
        description: str = "",
    ) -> None:
        """Queue zeroing the source operand of a state variable write.

        Instead of NOPing the instruction, replaces the source constant with
        ``#0`` so the state variable's *previous* (entry) value is killed.
        """
        self.modifications.append(
            QueuedModification(
                mod_type=ModificationType.INSN_ZERO_STATE_WRITE,
                block_serial=block_serial,
                insn_ea=insn_ea,
                priority=900,
                description=description
                or f"zero state write at {hex(insn_ea)} in block {block_serial}",
            )
        )
        logger.debug(
            "Queued zero state write: block %d, ea=%s", block_serial, hex(insn_ea)
        )
        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_QUEUE_ADDED,
                self._mod_payload(self.modifications[-1]),
            )

    def queue_promote_operand_to_scalar(
        self,
        block_serial: int,
        host_ea: int,
        host_opcode: int,
        operand_side: str,
        description: str = "",
    ) -> None:
        """Queue promotion of a fused sub-instruction operand into a fresh
        scalar (kreg) standalone instruction.

        At apply-time, the host instruction's ``operand_side`` (``"l"`` or
        ``"r"``) — which must be a ``mop_d`` — is hoisted into a new
        instruction inserted before the host, with its result bound to a
        freshly-allocated kreg. The host's operand is then rewritten to
        reference that kreg. Defeats IDA's MMAT_LVARS DCE on fused
        load-add-store induction patterns.
        """
        if operand_side not in ("l", "r"):
            raise ValueError(f"operand_side must be 'l' or 'r', got {operand_side!r}")
        self.modifications.append(
            QueuedModification(
                mod_type=ModificationType.INSN_PROMOTE_OPERAND_TO_SCALAR,
                block_serial=block_serial,
                insn_ea=host_ea,
                host_opcode=host_opcode,
                operand_side=operand_side,
                priority=900,
                description=description
                or (
                    f"promote operand {operand_side} of insn at "
                    f"{hex(host_ea)} in block {block_serial}"
                ),
            )
        )
        logger.debug(
            "Queued promote_operand_to_scalar: block %d, host_ea=%s, side=%s",
            block_serial,
            hex(host_ea),
            operand_side,
        )
        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_QUEUE_ADDED,
                self._mod_payload(self.modifications[-1]),
            )

    def queue_scalarize_local_alias_access(
        self,
        block_serial: int,
        host_ea: int,
        host_opcode: int,
        alias_token: str,
        base_token: str,
        host_text_sha1: str | None = None,
        value_size: int | None = None,
        description: str = "",
    ) -> None:
        """Queue scalarization of a proven local pointer alias access.

        The mutation rehydrates the current base-local mop from the live MBA at
        apply time and rewrites only the identified instruction.  It is kept as
        a queued instruction-only primitive so producer facts remain
        serializable and consumers do not perform ad hoc live surgery.
        """
        alias_token = _canonical_local_var_token(alias_token) or ""
        base_token = _canonical_local_var_token(base_token) or ""
        if not alias_token or not base_token:
            raise ValueError(
                "alias_token and base_token must be non-empty local tokens"
            )
        self.modifications.append(
            QueuedModification(
                mod_type=ModificationType.INSN_SCALARIZE_LOCAL_ALIAS_ACCESS,
                block_serial=block_serial,
                insn_ea=host_ea,
                host_opcode=host_opcode,
                alias_token=alias_token,
                base_token=base_token,
                host_text_sha1=str(host_text_sha1 or "") or None,
                value_size=int(value_size or 0) or None,
                priority=850,
                description=description
                or (
                    f"scalarize local alias {alias_token}->{base_token} at "
                    f"{hex(host_ea)} in block {block_serial}"
                ),
            )
        )
        logger.debug(
            "Queued scalarize_local_alias_access: block %d, host_ea=%s, alias=%s, base=%s",
            block_serial,
            hex(host_ea),
            alias_token,
            base_token,
        )
        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_QUEUE_ADDED,
                self._mod_payload(self.modifications[-1]),
            )

    def queue_retarget_output_store(
        self,
        block_serial: int,
        host_ea: int,
        host_opcode: int,
        alias_token: str,
        output_token: str,
        host_text_sha1: str | None = None,
        value_size: int | None = None,
        description: str = "",
    ) -> None:
        """Queue retargeting of a proven output-store address to the output pointer."""
        alias_token = _canonical_local_var_token(alias_token) or ""
        output_token = _canonical_local_var_token(output_token) or ""
        if not alias_token or not output_token:
            raise ValueError(
                "alias_token and output_token must be non-empty local tokens"
            )
        self.modifications.append(
            QueuedModification(
                mod_type=ModificationType.INSN_RETARGET_OUTPUT_STORE,
                block_serial=block_serial,
                insn_ea=host_ea,
                host_opcode=host_opcode,
                alias_token=alias_token,
                base_token=output_token,
                host_text_sha1=str(host_text_sha1 or "") or None,
                value_size=int(value_size or 0) or None,
                priority=845,
                description=description
                or (
                    f"retarget output store {alias_token}->{output_token} at "
                    f"{hex(host_ea)} in block {block_serial}"
                ),
            )
        )
        logger.debug(
            "Queued retarget_output_store: block %d, host_ea=%s, alias=%s, output=%s",
            block_serial,
            hex(host_ea),
            alias_token,
            output_token,
        )
        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_QUEUE_ADDED,
                self._mod_payload(self.modifications[-1]),
            )

    def queue_lower_conditional_state_transition(
        self,
        *,
        source_serial: int,
        old_dispatcher_serial: int,
        rewrite_from_ea: int,
        condition_operand: object,
        false_target_serial: int,
        true_target_serial: int,
        proof_id: str | None = None,
        state_register: int | None = None,
        state_size: int | None = None,
        false_state: int | None = None,
        true_state: int | None = None,
        false_state_write_ea: int | None = None,
        true_state_write_ea: int | None = None,
        description: str = "",
        rule_priority: int = 0,
    ) -> None:
        """Queue replacement of a state-write-to-dispatcher edge with a 2-way edge."""
        self.modifications.append(
            QueuedModification(
                mod_type=ModificationType.LOWER_CONDITIONAL_STATE_TRANSITION,
                block_serial=source_serial,
                new_target=true_target_serial,
                old_target=old_dispatcher_serial,
                rewrite_from_ea=rewrite_from_ea,
                condition_operand=condition_operand,
                false_target=false_target_serial,
                true_target=true_target_serial,
                proof_id=proof_id,
                state_register=state_register,
                state_size=state_size,
                false_state=false_state,
                true_state=true_state,
                false_state_write_ea=false_state_write_ea,
                true_state_write_ea=true_state_write_ea,
                priority=10,
                rule_priority=rule_priority,
                description=description
                or (
                    f"lower conditional state transition {source_serial}: "
                    f"{old_dispatcher_serial}->{false_target_serial}/{true_target_serial}"
                ),
            )
        )
        logger.debug(
            "Queued lower_conditional_state_transition: src=%d old=%d false=%d true=%d ea=%s",
            source_serial,
            old_dispatcher_serial,
            false_target_serial,
            true_target_serial,
            hex(rewrite_from_ea),
        )
        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_QUEUE_ADDED,
                self._mod_payload(self.modifications[-1]),
            )

    def queue_materialize_zero_way_conditional(
        self,
        *,
        source_serial: int,
        predicate_ea: int,
        taken_target_serial: int,
        fallthrough_target_serial: int,
        description: str = "",
        rule_priority: int = 0,
    ) -> None:
        """Queue atomic binding of a generated zero-way ``m_jcnd``.

        At ``MMAT_GENERATED`` Hex-Rays still represents the native conditional
        target as ``mop_v`` and has not built either CFG successor.  The
        mutation preserves the condition instruction verbatim, replaces only
        its destination with the proven taken block, and creates the adjacent
        fallthrough helper required by the MBA verifier.
        """
        self.modifications.append(
            QueuedModification(
                mod_type=ModificationType.MATERIALIZE_ZERO_WAY_CONDITIONAL,
                block_serial=int(source_serial),
                new_target=int(taken_target_serial),
                conditional_target=int(taken_target_serial),
                fallthrough_target=int(fallthrough_target_serial),
                rewrite_from_ea=int(predicate_ea),
                priority=10,
                rule_priority=int(rule_priority),
                description=description
                or (
                    f"materialize zero-way conditional {source_serial}: "
                    f"taken={taken_target_serial} fallthrough={fallthrough_target_serial}"
                ),
            )
        )
        logger.debug(
            "Queued materialize_zero_way_conditional: src=%d ea=%s taken=%d fallthrough=%d",
            source_serial,
            hex(predicate_ea),
            taken_target_serial,
            fallthrough_target_serial,
        )
        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_QUEUE_ADDED,
                self._mod_payload(self.modifications[-1]),
            )

    def queue_materialize_zero_way_goto(
        self,
        *,
        source_serial: int,
        predicate_ea: int,
        target_serial: int,
        description: str = "",
        rule_priority: int = 0,
    ) -> None:
        """Queue atomic replacement of a generated zero-way transfer.

        The exact native transfer is removed together with its zero-way shape
        and replaced by one proven direct edge.  This operation is deliberately
        distinct from ``BLOCK_CONVERT_TO_GOTO`` because a zero-way conditional
        cannot pass through an intermediate one-way conditional CFG state.
        """
        self.modifications.append(
            QueuedModification(
                mod_type=ModificationType.MATERIALIZE_ZERO_WAY_GOTO,
                block_serial=int(source_serial),
                new_target=int(target_serial),
                rewrite_from_ea=int(predicate_ea),
                priority=10,
                rule_priority=int(rule_priority),
                description=description
                or (
                    f"materialize zero-way goto {source_serial}: "
                    f"predicate=0x{int(predicate_ea):X} target={target_serial}"
                ),
            )
        )
        logger.debug(
            "Queued materialize_zero_way_goto: src=%d ea=%s target=%d",
            source_serial,
            hex(predicate_ea),
            target_serial,
        )
        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_QUEUE_ADDED,
                self._mod_payload(self.modifications[-1]),
            )

    def queue_normalize_nway_dispatcher_exit(
        self,
        block_serial: int,
        dispatcher_entry_serial: int,
        *,
        keep_target_serial: int | None = None,
        description: str = "",
        rule_priority: int = 0,
    ) -> None:
        """Queue a degenerate BLT_NWAY null-tail dispatcher-exit downgrade."""
        self.modifications.append(
            QueuedModification(
                mod_type=ModificationType.NORMALIZE_NWAY_DISPATCHER_EXIT,
                block_serial=block_serial,
                old_target=dispatcher_entry_serial,
                new_target=keep_target_serial,
                dispatcher_entry_serial=dispatcher_entry_serial,
                keep_target_serial=keep_target_serial,
                priority=15,
                rule_priority=rule_priority,
                description=description
                or (
                    f"normalize NWAY dispatcher exit {block_serial}: "
                    f"drop dispatcher {dispatcher_entry_serial}"
                ),
            )
        )
        logger.debug(
            "Queued normalize_nway_dispatcher_exit: block=%d dispatcher=%d keep=%s",
            block_serial,
            dispatcher_entry_serial,
            keep_target_serial,
        )
        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_QUEUE_ADDED,
                self._mod_payload(self.modifications[-1]),
            )

    def queue_bypass_dispatcher_trampoline(
        self,
        source_serial: int,
        trampoline_serial: int,
        target_serial: int,
        *,
        description: str = "",
        rule_priority: int = 0,
    ) -> None:
        """Queue an exact-edge bypass from a dispatcher trampoline to its target."""
        self.modifications.append(
            QueuedModification(
                mod_type=ModificationType.BYPASS_DISPATCHER_TRAMPOLINE,
                block_serial=source_serial,
                old_target=trampoline_serial,
                new_target=target_serial,
                priority=10,
                rule_priority=rule_priority,
                description=description
                or (
                    f"bypass dispatcher trampoline {source_serial}: "
                    f"{trampoline_serial}->{target_serial}"
                ),
            )
        )
        logger.debug(
            "Queued bypass_dispatcher_trampoline: src=%d trampoline=%d target=%d",
            source_serial,
            trampoline_serial,
            target_serial,
        )
        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_QUEUE_ADDED,
                self._mod_payload(self.modifications[-1]),
            )

    def queue_canonicalize_jtbl_case_overlap(
        self,
        jtbl_serial: int,
        retarget_map: tuple[tuple[int, int], ...],
        *,
        deduplicate: bool = False,
        description: str = "",
        rule_priority: int = 0,
    ) -> None:
        """Queue a jump-table case retarget/coalescing operation."""
        self.modifications.append(
            QueuedModification(
                mod_type=ModificationType.CANONICALIZE_JTBL_CASE_OVERLAP,
                block_serial=jtbl_serial,
                retarget_map=tuple((int(old), int(new)) for old, new in retarget_map),
                deduplicate_cases=bool(deduplicate),
                priority=15,
                rule_priority=rule_priority,
                description=description
                or (
                    f"canonicalize jump-table overlap {jtbl_serial}: "
                    f"{len(retarget_map)} retargets"
                ),
            )
        )
        logger.debug(
            "Queued canonicalize_jtbl_case_overlap: block=%d retargets=%s deduplicate=%s",
            jtbl_serial,
            retarget_map,
            deduplicate,
        )
        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_QUEUE_ADDED,
                self._mod_payload(self.modifications[-1]),
            )

    def queue_phase_cycle_lowering(
        self,
        *,
        header_entries: tuple[int, ...],
        header_target: int,
        body_entries: tuple[int, ...],
        body_target: int,
        next_phase_entries: tuple[int, ...],
        next_phase_target: int,
        terminal_entries: tuple[int, ...] = (),
        terminal_target: int | None = None,
        description: str = "",
        rule_priority: int = 0,
    ) -> None:
        """Queue guarded one-way redirects for a resolved dispatcher phase cycle."""
        primary = (
            header_entries[0]
            if header_entries
            else body_entries[0]
            if body_entries
            else next_phase_entries[0]
            if next_phase_entries
            else terminal_entries[0]
            if terminal_entries
            else 0
        )
        self.modifications.append(
            QueuedModification(
                mod_type=ModificationType.PHASE_CYCLE_LOWERING,
                block_serial=primary,
                priority=20,
                rule_priority=rule_priority,
                phase_header_entries=tuple(header_entries),
                phase_header_target=header_target,
                phase_body_entries=tuple(body_entries),
                phase_body_target=body_target,
                phase_next_phase_entries=tuple(next_phase_entries),
                phase_next_phase_target=next_phase_target,
                phase_terminal_entries=tuple(terminal_entries),
                phase_terminal_target=terminal_target,
                description=description or "lower dispatcher phase cycle",
            )
        )
        logger.debug(
            "Queued phase_cycle_lowering: header=%s->%d body=%s->%d next=%s->%d terminal=%s->%s",
            header_entries,
            header_target,
            body_entries,
            body_target,
            next_phase_entries,
            next_phase_target,
            terminal_entries,
            terminal_target,
        )
        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_QUEUE_ADDED,
                self._mod_payload(self.modifications[-1]),
            )

    def queue_create_and_redirect(
        self,
        source_block_serial: int,
        final_target_serial: int,
        instructions_to_copy: list | tuple,
        is_0_way: bool = False,
        expected_serial: int | None = None,
        description: str = "",
        old_target_serial: int | None = None,
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
            old_target_serial: Existing successor edge on source being replaced.
                Required when source is 2-way (disambiguates which arm of the
                conditional jump to redirect). Defaults to ``final_target_serial``
                when source is 1-way.

        Stage requirement: this insert marks the mba graph/chains cache
        structurally dirty; if applied outside the GLBOPT1 optblock pass the
        decompiler raises INTERR 50346 at ctree. See ``apply()`` (Mutation-stage
        requirement) for the full rationale and the optblock_t pattern.
        """
        self.modifications.append(
            QueuedModification(
                mod_type=ModificationType.BLOCK_CREATE_WITH_REDIRECT,
                block_serial=source_block_serial,
                new_target=final_target_serial,  # Used as reference block for insert_nop_blk
                final_target=final_target_serial,
                instructions_to_copy=instructions_to_copy,
                is_0_way=is_0_way,
                expected_serial=expected_serial,
                old_target=old_target_serial,
                priority=5,  # Very high priority - create blocks before other changes
                description=description
                or f"create block after {source_block_serial} -> {final_target_serial}",
            )
        )
        logger.debug(
            "Queued create_and_redirect: %d -> (new) -> %d with %d instructions",
            source_block_serial,
            final_target_serial,
            len(instructions_to_copy),
        )
        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_QUEUE_ADDED,
                self._mod_payload(self.modifications[-1]),
            )

    def queue_create_conditional_redirect(
        self,
        source_blk_serial: int,
        ref_blk_serial: int,
        conditional_target_serial: int,
        fallthrough_target_serial: int,
        old_target_serial: int | None = None,
        instructions_to_copy: list | tuple | None = None,
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

        Uses the proven conditional-clone materialization pattern:
        1. Duplicate the conditional block (preserving tail instruction)
        2. Create a NOP-goto block as fallthrough (IDA requires physical adjacency)
        3. Wire conditional target directly
        4. Redirect source block to the new conditional block

        Args:
            source_blk_serial: Block whose successor will be changed to new block
            ref_blk_serial: Block to copy instructions from (should be conditional)
            conditional_target_serial: Target for jcc taken branch
            fallthrough_target_serial: Target for fallthrough (via NOP-goto)
            old_target_serial: Optional current source successor that must
                still be present when the queued modification is applied.
            instructions_to_copy: Optional instructions to prepend to the cloned
                conditional block before its original body executes.
            expected_conditional_serial: Expected final serial for cloned conditional block
            expected_fallthrough_serial: Expected final serial for NOP fallthrough block
            description: Optional description for logging
        """
        self.modifications.append(
            QueuedModification(
                mod_type=ModificationType.BLOCK_CREATE_WITH_CONDITIONAL_REDIRECT,
                block_serial=source_blk_serial,
                new_target=ref_blk_serial,  # Reference block to copy from
                conditional_target=conditional_target_serial,
                fallthrough_target=fallthrough_target_serial,
                old_target=old_target_serial,
                instructions_to_copy=instructions_to_copy,
                expected_conditional_serial=expected_conditional_serial,
                expected_fallthrough_serial=expected_fallthrough_serial,
                priority=5,  # Very high priority - create blocks before other changes
                description=description
                or (
                    f"create conditional block after {source_blk_serial} "
                    f"-> jcc:{conditional_target_serial} / fallthrough:{fallthrough_target_serial}"
                ),
            )
        )
        logger.debug(
            "Queued create_conditional_redirect: %d -> (new conditional) "
            "-> jcc:%d / fallthrough:%d",
            source_blk_serial,
            conditional_target_serial,
            fallthrough_target_serial,
        )
        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_QUEUE_ADDED,
                self._mod_payload(self.modifications[-1]),
            )
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
        conditional_target: int | None = None,
        fallthrough_target: int | None = None,
        expected_serial: int | None = None,
        expected_secondary_serial: int | None = None,
        original_redirect_target: int | None = None,
        description: str = "",
        rule_priority: int = 0,
    ) -> None:
        """Queue duplication of ``source_block_serial`` and redirect ``pred_serial`` to the clone.

        If *original_redirect_target* is given, the **original** block's
        successor is also redirected to that serial after the clone is wired,
        making the operation fully atomic (clone + redirect clone + redirect
        original).
        """
        self.modifications.append(
            QueuedModification(
                mod_type=ModificationType.BLOCK_DUPLICATE_AND_REDIRECT,
                block_serial=source_block_serial,
                new_target=target_serial,
                via_pred=pred_serial,
                conditional_target=conditional_target,
                fallthrough_target=fallthrough_target,
                expected_serial=expected_serial,
                expected_secondary_serial=expected_secondary_serial,
                original_redirect_target=original_redirect_target,
                priority=5,
                rule_priority=rule_priority,
                description=description
                or (
                    f"duplicate block src={source_block_serial} pred={pred_serial} "
                    f"target={target_serial}"
                ),
            )
        )
        logger.debug(
            "Queued duplicate_block: src=%d pred=%s target=%s cond=%s ft=%s expected=%s secondary=%s",
            source_block_serial,
            pred_serial,
            target_serial,
            conditional_target,
            fallthrough_target,
            expected_serial,
            expected_secondary_serial,
        )
        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_QUEUE_ADDED,
                self._mod_payload(self.modifications[-1]),
            )

    def queue_duplicate_replay_and_redirect(
        self,
        *,
        source_block_serial: int,
        dispatcher_entry_serial: int,
        per_pred_replays: tuple,
        description: str = "",
        rule_priority: int = 0,
    ) -> None:
        """Queue atomic duplicate-group replay materialization.

        Each row is ``(pred, target, replay_serial, clone_serial, instructions)``.
        The first row keeps the original source block and has ``clone_serial`` as
        ``None``; later rows clone the shared source before routing through their
        replay block.
        """
        self.modifications.append(
            QueuedModification(
                mod_type=ModificationType.BLOCK_DUPLICATE_REPLAY_AND_REDIRECT,
                block_serial=source_block_serial,
                new_target=dispatcher_entry_serial,
                replay_entries=per_pred_replays,
                priority=5,
                rule_priority=rule_priority,
                description=description
                or (
                    f"duplicate replay src={source_block_serial} "
                    f"dispatcher={dispatcher_entry_serial} rows={len(per_pred_replays)}"
                ),
            )
        )
        logger.debug(
            "Queued duplicate_replay_and_redirect: src=%d dispatcher=%d rows=%d",
            source_block_serial,
            dispatcher_entry_serial,
            len(per_pred_replays),
        )
        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_QUEUE_ADDED,
                self._mod_payload(self.modifications[-1]),
            )

    def queue_clone_conditional_as_goto(
        self,
        *,
        source_block_serial: int,
        pred_serial: int,
        goto_target_serial: int,
        expected_serial: int | None = None,
        description: str = "",
        rule_priority: int = 0,
    ) -> None:
        """Queue FixPredecessor's clone-as-goto primitive.

        The operation clones ``source_block_serial``, clears inherited clone
        predecessors, converts only the clone to a one-way goto targeting
        ``goto_target_serial``, then redirects the selected one-way predecessor
        to the clone.  The source conditional block remains unchanged.
        """
        self.modifications.append(
            QueuedModification(
                mod_type=ModificationType.CLONE_CONDITIONAL_AS_GOTO,
                block_serial=source_block_serial,
                new_target=goto_target_serial,
                via_pred=pred_serial,
                expected_serial=expected_serial,
                priority=5,
                rule_priority=rule_priority,
                description=description
                or (
                    f"clone conditional as goto src={source_block_serial} "
                    f"pred={pred_serial} target={goto_target_serial}"
                ),
            )
        )
        logger.debug(
            "Queued clone_conditional_as_goto: src=%d pred=%d target=%d expected=%s",
            source_block_serial,
            pred_serial,
            goto_target_serial,
            expected_serial,
        )
        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_QUEUE_ADDED,
                self._mod_payload(self.modifications[-1]),
            )

    def queue_clone_conditional_as_goto_from_branch_arm(
        self,
        *,
        source_block_serial: int,
        pred_serial: int,
        pred_arm: int,
        goto_target_serial: int,
        expected_serial: int | None = None,
        description: str = "",
        rule_priority: int = 0,
    ) -> None:
        """Queue FixPredecessor's 2-way branch-arm clone-as-goto primitive.

        Sibling of :meth:`queue_clone_conditional_as_goto` for the case where
        the predecessor is a 2-way conditional with a known arm targeting
        ``source_block_serial``.  The operation
        clones the source, clears inherited clone predecessors, converts the
        clone to a one-way goto targeting ``goto_target_serial``, then
        rewires the selected predecessor arm to the clone.  ``pred_arm == 1``
        uses the explicit conditional branch helper; ``pred_arm == 0`` uses the
        fallthrough helper-block path.
        """
        if pred_arm not in (0, 1):
            raise ValueError(
                "queue_clone_conditional_as_goto_from_branch_arm currently "
                f"only supports pred_arm=0 or 1, got pred_arm={pred_arm}"
            )
        self.modifications.append(
            QueuedModification(
                mod_type=ModificationType.CLONE_CONDITIONAL_AS_GOTO_FROM_BRANCH_ARM,
                block_serial=source_block_serial,
                new_target=goto_target_serial,
                via_pred=pred_serial,
                pred_arm=pred_arm,
                expected_serial=expected_serial,
                priority=5,
                rule_priority=rule_priority,
                description=description
                or (
                    f"clone conditional as goto from arm src={source_block_serial} "
                    f"pred={pred_serial} arm={pred_arm} target={goto_target_serial}"
                ),
            )
        )
        logger.debug(
            "Queued clone_conditional_as_goto_from_branch_arm: "
            "src=%d pred=%d arm=%d target=%d expected=%s",
            source_block_serial,
            pred_serial,
            pred_arm,
            goto_target_serial,
            expected_serial,
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
        source_new_target: int | None = None,
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
            clone_until: Optional strict 1-way corridor endpoint. When set, the
                backend clones the corridor ``src_block .. clone_until`` and
                rewires ``via_pred`` to the first clone.
            source_new_target: Optional target for the original source block
                after cloning a corridor.
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

        self.modifications.append(
            QueuedModification(
                mod_type=ModificationType.EDGE_REDIRECT_VIA_PRED_SPLIT,
                block_serial=src_block,
                new_target=new_target,
                priority=12 if clone_until is not None else 8,
                description=description
                or (
                    f"edge redirect via pred split: pred={via_pred} src={src_block} "
                    f"{old_target} -> {new_target}"
                ),
                rule_priority=rule_priority,
                src_block=src_block,
                old_target=old_target,
                via_pred=via_pred,
                clone_until=clone_until,
                source_new_target=source_new_target,
            )
        )
        logger.debug(
            "Queued edge_redirect_via_pred_split: pred=%d src=%d old=%d new=%d "
            "(rule_priority=%d)",
            via_pred,
            src_block,
            old_target,
            new_target,
            rule_priority,
        )
        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_QUEUE_ADDED,
                self._mod_payload(self.modifications[-1]),
            )

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
        self.modifications.append(
            QueuedModification(
                mod_type=ModificationType.EDGE_SPLIT_TRAMPOLINE,
                block_serial=via_pred,
                new_target=new_target,
                priority=5,
                description=description
                or (
                    f"edge split trampoline: pred={via_pred} src={source_block} "
                    f"{old_target}->{new_target} serial={expected_serial}"
                ),
                rule_priority=rule_priority,
                src_block=source_block,
                old_target=old_target,
                via_pred=via_pred,
                expected_serial=expected_serial,
            )
        )
        logger.debug(
            "Queued edge_split_trampoline: pred=%d src=%d old=%d new=%d serial=%d",
            via_pred,
            source_block,
            old_target,
            new_target,
            expected_serial,
        )
        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_QUEUE_ADDED,
                self._mod_payload(self.modifications[-1]),
            )

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
        self.modifications.append(
            QueuedModification(
                mod_type=ModificationType.EDGE_REMOVE,
                block_serial=from_serial,
                new_target=to_serial,
                priority=15,  # After goto changes (10) but before convert-to-goto (20)
                description=description or f"remove edge {from_serial}->{to_serial}",
            )
        )
        logger.debug(
            "Queued edge remove: %d -> %d",
            from_serial,
            to_serial,
        )
        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_QUEUE_ADDED,
                self._mod_payload(self.modifications[-1]),
            )

    def run_deep_cleaning(self, *, call_mba_combine_block: bool = True) -> int:
        """Run the central CFG cleanup primitive through the mutation backend."""
        return mba_deep_cleaning(
            self.mba,
            call_mba_combine_block=call_mba_combine_block,
        )

    def ensure_last_block_is_goto(self, *, verify: bool = True) -> int:
        """Normalize the trailing block through the central mutation backend."""
        return ensure_last_block_is_goto(self.mba, verify=verify)

    def ensure_child_has_unconditional_father(
        self,
        father_serial: int,
        child_serial: int,
        *,
        verify: bool = True,
    ) -> int:
        """Ensure a child has an unconditional predecessor via the backend."""
        father = self.mba.get_mblock(int(father_serial))
        child = self.mba.get_mblock(int(child_serial))
        return ensure_child_has_an_unconditional_father(
            father,
            child,
            verify=verify,
        )

    def create_standalone_block(
        self,
        *,
        ref_serial: int,
        blk_ins: list | tuple | None = None,
        target_serial: int | None = None,
        is_0_way: bool = False,
        verify: bool = True,
        stable_identity: StableBlockIdentity | None = None,
        handle_provenance: BlockHandleProvenance = BlockHandleProvenance.NATIVE,
    ) -> int | None:
        """Create a standalone block and return its live serial."""
        resolved_ref_serial = self._resolve_serial(int(ref_serial))
        if resolved_ref_serial is None:
            return None
        ref_blk = self.mba.get_mblock(int(resolved_ref_serial))
        if ref_blk is None:
            logger.warning(
                "create_standalone_block: ref block %d not found", ref_serial
            )
            return None
        old_qty = int(self.mba.qty)
        self._begin_mutation_batch(
            serial_quantity=old_qty,
            kind=StructuralMutationKind.BLOCK_INSERT,
            description=(
                "create standalone native block"
                if stable_identity is not None
                else "create standalone block"
            ),
        )
        try:
            new_blk = create_standalone_block(
                ref_blk=ref_blk,
                blk_ins=list(blk_ins or ()),
                target_serial=target_serial,
                is_0_way=is_0_way,
                verify=verify,
            )
            if new_blk is None:
                self._finish_mutation_batch(0)
                return None
            created_handle = None
            if stable_identity is not None:
                gateway = self._mutation_gateway
                if gateway is None:
                    raise RuntimeError(
                        "native block creation requires a mutation gateway"
                    )
                created_handle = gateway.identity_index.create_native_handle(
                    stable_identity,
                    provenance=handle_provenance,
                )
            self._record_serial_insertion(
                int(new_blk.serial),
                old_qty,
                created=created_handle,
            )
            return int(new_blk.serial)
        except Exception:
            self._finish_mutation_batch(0)
            raise

    def commit_immediate_mutations(self) -> None:
        """Commit structural writes performed by the immediate helper methods."""
        gateway = self._mutation_gateway
        if gateway is not None and gateway.active:
            gateway.commit()

    def copy_block_keep_now(
        self,
        ref_blk: ida_hexrays.mblock_t,
        dest_serial: int,
        *,
        cpblk_flags: int = CPBLK_MINREF,
    ) -> ida_hexrays.mblock_t | None:
        """Copy a block while preserving the backend MBL_KEEP behavior.

        Defaults to ``CPBLK_MINREF`` so the copy keeps its terminating
        ``m_goto`` (see ``copy_block_keep``); IDA's library default would
        strip it via ``CPBLK_OPTJMP``.
        """
        return copy_block_keep(
            self.mba, ref_blk, int(dest_serial), cpblk_flags=int(cpblk_flags)
        )

    def split_block_now(
        self,
        block: ida_hexrays.mblock_t,
        start_insn: ida_hexrays.minsn_t,
    ) -> ida_hexrays.mblock_t | None:
        """Split one live block and publish its serial shift atomically."""
        old_qty = int(self.mba.qty)
        original_serial = int(block.serial)
        self._begin_mutation_batch(
            serial_quantity=old_qty,
            kind=StructuralMutationKind.BLOCK_REPLACE,
            description="split live block",
        )
        gateway = self._mutation_gateway
        if gateway is None:
            raise RuntimeError("block split requires a mutation gateway")
        original_handle = gateway.identity_index.handle_for_serial(original_serial)
        if original_handle is None:
            self._finish_mutation_batch(0)
            raise RuntimeError(
                f"block split cannot bind original serial {original_serial}"
            )
        try:
            new_block = self.mba.split_block(block, start_insn)
            if new_block is None:
                self._finish_mutation_batch(0)
                return None
            returned_tail_serial = int(new_block.serial)
            retained_block = self.mba.get_mblock(original_serial)
            returned_tail = self.mba.get_mblock(returned_tail_serial)
            if retained_block is None or returned_tail is None:
                self._finish_mutation_batch(0)
                raise RuntimeError("block split SDK result is not live in the MBA")

            retained_handle = None
            tail_handle = None
            original_identity = original_handle.stable_identity
            if (
                original_identity is not None
                and original_identity.exact_instruction_eas
            ):
                retained_eas = frozenset(
                    int(instruction.ea)
                    for instruction in self._block_instructions(retained_block)
                    if 0 <= int(getattr(instruction, "ea", -1)) < 0xFFFFFFFFFFFFFFFF
                )
                tail_eas = frozenset(
                    int(instruction.ea)
                    for instruction in self._block_instructions(returned_tail)
                    if 0 <= int(getattr(instruction, "ea", -1)) < 0xFFFFFFFFFFFFFFFF
                )
                if (
                    retained_eas
                    and tail_eas
                    and retained_eas.isdisjoint(tail_eas)
                    and retained_eas | tail_eas
                    == original_identity.exact_instruction_eas
                ):
                    retained_handle = gateway.identity_index.create_native_handle(
                        StableBlockIdentity.from_instruction_eas(
                            retained_eas,
                            native_key=original_identity.native_key,
                        ),
                        provenance=original_handle.provenance,
                    )
                    tail_handle = gateway.identity_index.create_native_handle(
                        StableBlockIdentity.from_instruction_eas(
                            tail_eas,
                            native_key=original_identity.native_key,
                        ),
                        provenance=original_handle.provenance,
                    )
            if retained_handle is None or tail_handle is None:
                retained_handle = (
                    gateway.identity_index.create_observed_ephemeral_handle()
                )
                tail_handle = gateway.identity_index.create_observed_ephemeral_handle()
            gateway.record_split(
                original=original_handle,
                retained=retained_handle,
                created_tail=tail_handle,
                returned_tail_serial=returned_tail_serial,
            )
            self._finish_mutation_batch(1)
            return new_block
        except Exception:
            self._finish_mutation_batch(0)
            raise

    def mark_blocks_dirty_now(
        self,
        *blocks: ida_hexrays.mblock_t | None,
        mark_chains: bool = True,
    ) -> None:
        """Mark live block lists and optionally chains dirty from the backend."""
        for blk in blocks:
            if blk is None:
                continue
            try:
                if int(getattr(blk, "serial", -1)) != int(self.mba.qty) - 1:
                    blk.mark_lists_dirty()
            except Exception:
                continue
        if mark_chains:
            self.mba.mark_chains_dirty()

    def replace_instruction_with_constant_now(
        self,
        block: ida_hexrays.mblock_t,
        *,
        instruction_index: int,
        expected_ea: int,
        expected_opcode: int,
        constant_value: int,
        value_size: int,
    ) -> ida_hexrays.minsn_t:
        """Replace one exactly indexed load with ``m_mov #constant, dest``."""
        instructions = self._block_instructions(block)
        instruction_index = int(instruction_index)
        if not 0 <= instruction_index < len(instructions):
            raise ValueError("constant replacement index is outside the live block")
        target = instructions[instruction_index]
        if (
            int(target.ea) != int(expected_ea)
            or int(target.opcode) != int(expected_opcode)
        ):
            raise ValueError(
                "constant replacement index changed after immutable preflight; "
                f"blk{int(block.serial)}@0x{int(block.start):X} "
                f"index={instruction_index} expected=(0x{int(expected_ea):X},"
                f"{int(expected_opcode)}) actual=(0x{int(target.ea):X},"
                f"{int(target.opcode)})"
            )
        value_size = int(value_size)
        if value_size <= 0:
            raise ValueError("constant replacement requires a positive value size")
        original = ida_hexrays.minsn_t(target)
        target.opcode = int(ida_hexrays.m_mov)
        target.l.make_number(
            int(constant_value) & ((1 << (value_size * 8)) - 1),
            value_size,
            int(expected_ea),
        )
        target.r.erase()
        block.mark_lists_dirty()
        self.mba.mark_chains_dirty()
        return original

    def replace_instruction_left_global_with_constant_now(
        self,
        block: ida_hexrays.mblock_t,
        *,
        instruction_index: int,
        expected_ea: int,
        expected_opcode: int,
        expected_data_ea: int,
        constant_value: int,
        value_size: int,
    ) -> ida_hexrays.minsn_t:
        """Replace only one proved left-side global operand with a constant."""
        instructions = self._block_instructions(block)
        instruction_index = int(instruction_index)
        if not 0 <= instruction_index < len(instructions):
            raise ValueError("constant replacement index is outside the live block")
        target = instructions[instruction_index]
        left = target.l
        if (
            int(target.ea) != int(expected_ea)
            or int(target.opcode) != int(expected_opcode)
            or int(left.t) != int(ida_hexrays.mop_v)
            or int(left.g) != int(expected_data_ea)
        ):
            raise ValueError(
                "left-global constant replacement changed after immutable preflight; "
                f"blk{int(block.serial)}@0x{int(block.start):X} "
                f"index={instruction_index} expected=(0x{int(expected_ea):X},"
                f"{int(expected_opcode)},0x{int(expected_data_ea):X})"
            )
        value_size = int(value_size)
        if value_size <= 0:
            raise ValueError("constant replacement requires a positive value size")
        original = ida_hexrays.minsn_t(target)
        left.make_number(
            int(constant_value) & ((1 << (value_size * 8)) - 1),
            value_size,
            int(expected_ea),
        )
        block.mark_lists_dirty()
        self.mba.mark_chains_dirty()
        return original

    def restore_instruction_from_snapshot_now(
        self,
        block: ida_hexrays.mblock_t,
        *,
        instruction_index: int,
        expected_ea: int,
        expected_opcode: int,
        original: ida_hexrays.minsn_t,
    ) -> None:
        """Restore one in-place instruction from its exact SDK snapshot."""
        instructions = self._block_instructions(block)
        instruction_index = int(instruction_index)
        if not 0 <= instruction_index < len(instructions):
            raise ValueError("constant rollback index is outside the live block")
        target = instructions[instruction_index]
        if (
            int(target.ea) != int(expected_ea)
            or int(target.opcode)
            not in {int(expected_opcode), int(original.opcode)}
        ):
            raise ValueError(
                "constant rollback index differs from the applied replacement"
            )
        target.opcode = int(original.opcode)
        target.ea = int(original.ea)
        target.iprops = int(original.iprops)
        target.l.assign(original.l)
        target.r.assign(original.r)
        target.d.assign(original.d)
        block.mark_lists_dirty()
        self.mba.mark_chains_dirty()

    @staticmethod
    def _block_instructions(block: ida_hexrays.mblock_t) -> tuple[object, ...]:
        instructions: list[object] = []
        instruction = block.head
        while instruction is not None:
            instructions.append(instruction)
            if instruction is block.tail:
                break
            instruction = instruction.next
        return tuple(instructions)

    def remove_all_instructions_now(self, block: ida_hexrays.mblock_t) -> None:
        """Remove every instruction through the central mutation backend."""
        for instruction in self._block_instructions(block):
            block.make_nop(instruction)
            block.remove_from_block(instruction)

    def replace_all_instructions_now(
        self,
        block: ida_hexrays.mblock_t,
        instructions: tuple[ida_hexrays.minsn_t, ...],
        *,
        mark_dirty: bool = True,
    ) -> None:
        """Replace one block body through the central mutation backend."""
        self.remove_all_instructions_now(block)
        for instruction in instructions:
            block.insert_into_block(instruction, block.tail)
        if mark_dirty:
            block.mark_lists_dirty()
            self.mba.mark_chains_dirty()

    def replace_instruction_suffix_from_index_now(
        self,
        block: ida_hexrays.mblock_t,
        *,
        cut_index: int,
        expected_ea: int,
        expected_opcode: int,
        replacement: ida_hexrays.minsn_t,
        mark_dirty: bool = True,
    ) -> None:
        """Replace an exactly indexed suffix after semantic preflight."""
        instructions = self._block_instructions(block)
        cut_index = int(cut_index)
        if not 0 <= cut_index < len(instructions):
            raise ValueError("instruction suffix index is outside the live block")
        cut = instructions[cut_index]
        if int(cut.ea) != int(expected_ea) or int(cut.opcode) != int(expected_opcode):
            raise ValueError(
                "instruction suffix index changed after semantic preflight; "
                f"blk{int(block.serial)}@0x{int(block.start):X} "
                f"index={cut_index} expected=(0x{int(expected_ea):X},"
                f"{int(expected_opcode)}) actual=(0x{int(cut.ea):X},"
                f"{int(cut.opcode)})"
            )
        for instruction in instructions[cut_index:]:
            block.make_nop(instruction)
            block.remove_from_block(instruction)
        block.insert_into_block(replacement, block.tail)
        if mark_dirty:
            block.mark_lists_dirty()
            self.mba.mark_chains_dirty()

    def remove_nops_now(self, block: ida_hexrays.mblock_t) -> None:
        """Remove all explicit NOP instructions from a block."""
        for instruction in self._block_instructions(block):
            if int(instruction.opcode) == int(ida_hexrays.m_nop):
                block.remove_from_block(instruction)

    def replace_instruction_suffix_now(
        self,
        block: ida_hexrays.mblock_t,
        *,
        cut_ea: int,
        replacement: ida_hexrays.minsn_t,
    ) -> None:
        """Replace one uniquely EA-anchored detached suffix through this backend."""
        instructions = self._block_instructions(block)
        cut_indexes = tuple(
            index
            for index, instruction in enumerate(instructions)
            if int(instruction.ea) == int(cut_ea)
        )
        if len(cut_indexes) != 1:
            raise ValueError(
                "instruction suffix replacement requires one exact cut EA; "
                f"blk{int(block.serial)}@0x{int(block.start):X} "
                f"cut=0x{int(cut_ea):X} matches={len(cut_indexes)}"
            )
        for instruction in instructions[cut_indexes[0] :]:
            block.make_nop(instruction)
            block.remove_from_block(instruction)
        block.insert_into_block(replacement, block.tail)
        block.mark_lists_dirty()
        self.mba.mark_chains_dirty()

    def replace_instruction_tail_after_anchor_now(
        self,
        block: ida_hexrays.mblock_t,
        *,
        retained_ea: int,
        replacement: ida_hexrays.minsn_t,
    ) -> None:
        """Retain one contiguous anchor group and replace its detached tail."""
        instructions = self._block_instructions(block)
        retained_indexes = tuple(
            index
            for index, instruction in enumerate(instructions)
            if int(instruction.ea) == int(retained_ea)
        )
        if not retained_indexes or retained_indexes != tuple(
            range(retained_indexes[0], retained_indexes[-1] + 1)
        ):
            raise ValueError(
                "instruction tail replacement requires one contiguous retained "
                f"anchor group; blk{int(block.serial)}@0x{int(block.start):X} "
                f"anchor=0x{int(retained_ea):X} matches={retained_indexes!r}"
            )
        discarded = instructions[retained_indexes[-1] + 1 :]
        if not discarded:
            raise ValueError("instruction tail replacement requires a suffix")
        for instruction in discarded:
            block.make_nop(instruction)
            block.remove_from_block(instruction)
        block.insert_into_block(replacement, block.tail)
        block.mark_lists_dirty()
        self.mba.mark_chains_dirty()

    def insert_instruction_now(
        self,
        block: ida_hexrays.mblock_t,
        instruction: ida_hexrays.minsn_t,
        before: ida_hexrays.minsn_t | None,
        *,
        mark_dirty: bool = False,
    ) -> None:
        """Insert one instruction through the central mutation backend."""
        block.insert_into_block(instruction, before)
        if mark_dirty:
            block.mark_lists_dirty()

    def configure_block_now(
        self,
        block: ida_hexrays.mblock_t,
        *,
        block_type: int | None = None,
        flags: int | None = None,
        start_ea: int | None = None,
        end_ea: int | None = None,
    ) -> None:
        """Apply verifier-relevant block metadata through the mutation backend."""
        if block_type is not None:
            block.type = int(block_type)
        if flags is not None:
            block.flags = int(flags)
        if start_ea is not None:
            block.start = int(start_ea)
        if end_ea is not None:
            block.end = int(end_ea)

    def connect_blocks_now(
        self,
        source: ida_hexrays.mblock_t,
        target: ida_hexrays.mblock_t,
    ) -> None:
        """Add one explicit CFG edge and repair both adjacency sets."""
        self._begin_mutation_batch(
            serial_quantity=int(self.mba.qty),
            kind=StructuralMutationKind.EDGE_REDIRECT,
            description="connect live blocks",
        )
        gateway = self._mutation_gateway
        if gateway is None:
            raise RuntimeError("block connection requires a mutation gateway")
        try:
            source_handle = gateway.identity_index.handle_for_serial(int(source.serial))
            target_handle = gateway.identity_index.handle_for_serial(int(target.serial))
            source.succset.push_back(int(target.serial))
            target.predset.push_back(int(source.serial))
            source.mark_lists_dirty()
            target.mark_lists_dirty()
            gateway.record_edge_redirect(
                source=source_handle,
                target=target_handle,
            )
        except Exception:
            self._finish_mutation_batch(0)
            raise

    def make_displaced_fallthrough_explicit_now(
        self,
        block: ida_hexrays.mblock_t,
    ) -> None:
        """Close a non-adjacent one-way fallthrough with an explicit goto."""
        instruction_ea = int(self.mba.alloc_fict_ea(int(self.mba.entry_ea) + 1))
        goto_instruction = ida_hexrays.minsn_t(
            instruction_ea if block.tail is None else block.tail
        )
        block.insert_into_block(goto_instruction, block.tail)
        block.make_nop(goto_instruction)
        goto_instruction.opcode = int(ida_hexrays.m_goto)
        goto_instruction.l.make_blkref(int(block.succset[0]))
        goto_instruction.r.erase()
        goto_instruction.d.erase()
        goto_instruction.setaddr(instruction_ea)
        block.flags |= int(ida_hexrays.MBL_GOTO)
        block.mark_lists_dirty()

    def insert_nop_block_now(
        self,
        source_serial: int,
        *,
        force_adjacent: bool = False,
    ) -> int:
        """Insert an owned NOP block after a source block."""
        resolved_source_serial = self._resolve_serial(int(source_serial))
        if resolved_source_serial is None:
            raise RuntimeError(f"insert_nop_block: missing source {source_serial}")
        source = self.mba.get_mblock(int(resolved_source_serial))
        if source is None:
            raise RuntimeError(f"insert_nop_block: missing source {source_serial}")
        old_qty = int(self.mba.qty)
        self._begin_mutation_batch(
            serial_quantity=old_qty,
            kind=StructuralMutationKind.BLOCK_INSERT,
            description="insert NOP block",
        )
        try:
            inserted = insert_nop_blk(
                source,
                force_adjacent=bool(force_adjacent),
            )
            if inserted is None:
                self._finish_mutation_batch(0)
                raise RuntimeError("insert_nop_block: SDK returned no block")
            self._record_serial_insertion(int(inserted.serial), old_qty)
            return int(inserted.serial)
        except Exception:
            self._finish_mutation_batch(0)
            raise

    def redirect_one_way_now(
        self,
        source_serial: int,
        target_serial: int,
        *,
        verify: bool = False,
    ) -> bool:
        """Apply an immediate one-way redirect through the mutation backend."""
        self._begin_mutation_batch(
            serial_quantity=int(self.mba.qty),
            kind=StructuralMutationKind.EDGE_REDIRECT,
            description="redirect live one-way edge",
        )
        resolved_source = self._resolve_serial(int(source_serial))
        resolved_target = self._resolve_serial(int(target_serial))
        if resolved_source is None or resolved_target is None:
            self._finish_mutation_batch(0)
            return False
        source = self.mba.get_mblock(int(resolved_source))
        if source is None:
            self._finish_mutation_batch(0)
            return False
        gateway = self._mutation_gateway
        if gateway is None:
            raise RuntimeError("edge redirect requires a mutation gateway")
        try:
            changed = bool(
                change_1way_block_successor(
                    source,
                    int(resolved_target),
                    verify=verify,
                )
            )
            if not changed:
                self._finish_mutation_batch(0)
                return False
            gateway.record_edge_redirect(
                source=gateway.identity_index.handle_for_serial(int(resolved_source)),
                target=gateway.identity_index.handle_for_serial(int(resolved_target)),
            )
            return True
        except Exception:
            self._finish_mutation_batch(0)
            raise

    @staticmethod
    def _semantic_edge_block_label(block: object) -> str:
        return (
            f"blk{int(getattr(block, 'serial', -1))}"
            f"@0x{int(getattr(block, 'start', 0)):X}"
        )

    @staticmethod
    def _semantic_edge_conditional_diagnostic(
        operation: LogicalSemanticEdgeOperation,
        source_binding: LogicalBlockVersion,
        source: object,
    ) -> str:
        identity = source_binding.handle.stable_identity
        native_anchor = None
        if identity is not None:
            native_anchor = min(
                (int(ea) for ea in identity.exact_instruction_eas),
                default=int(identity.native_ranges.intervals[0].start_ea),
            )
        tail = getattr(source, "tail", None)
        observed_tail = (
            "none"
            if tail is None
            else (
                f"ea=0x{int(getattr(tail, 'ea', -1)):X} "
                f"opcode={int(getattr(tail, 'opcode', -1))}"
            )
        )
        return (
            f"operation={operation.description!r} "
            f"source={DeferredGraphModifier._semantic_edge_block_label(source)} "
            f"native@{('none' if native_anchor is None else f'0x{native_anchor:X}')} "
            f"expected_predicate=0x{int(operation.predicate_anchor_ea):X} "
            f"observed_tail={observed_tail}"
        )

    def _semantic_edge_call_fallthrough_diagnostic(
        self,
        operation: LogicalSemanticEdgeOperation,
        source_binding: LogicalBlockVersion,
        source: object,
    ) -> str:
        identity = source_binding.handle.stable_identity
        stable_identity = "none" if identity is None else identity.diagnostic_label()
        successors: list[str] = []
        quantity = int(getattr(self.mba, "qty", 0) or 0)
        for successor_serial in tuple(
            int(successor) for successor in getattr(source, "succset", ())
        ):
            successor = (
                self.mba.get_mblock(successor_serial)
                if 0 <= successor_serial < quantity
                else None
            )
            successors.append(
                (
                    f"blk{successor_serial}@<unbound>"
                    if successor is None
                    else self._semantic_edge_block_label(successor)
                )
            )
        tail = getattr(source, "tail", None)
        if tail is None:
            tail_diagnostic = (
                "tail_ea=none tail_native_origin=unmapped "
                "tail_opcode=none tail_dest_type=none"
            )
        else:
            tail_ea = int(getattr(tail, "ea", -1))
            tail_opcode = int(getattr(tail, "opcode", -1))
            tail_opcode_name = opcode_name(tail_opcode) or "unknown"
            destination = getattr(tail, "d", None)
            tail_dest_type = (
                "none"
                if destination is None
                else str(int(getattr(destination, "t", -1)))
            )
            tail_native_origin = (
                f"0x{tail_ea:X}"
                if identity is not None and tail_ea in identity.exact_instruction_eas
                else "unmapped"
            )
            tail_diagnostic = (
                f"tail_ea=0x{tail_ea:X} "
                f"tail_native_origin={tail_native_origin} "
                f"tail_opcode={tail_opcode_name}({tail_opcode}) "
                f"tail_dest_type={tail_dest_type}"
            )
        owned_call = sdk_owned_call(tail)
        if owned_call is None:
            owned_call_diagnostic = "owned_call=none"
        else:
            owned_call_ea = int(getattr(owned_call, "ea", -1))
            owned_call_opcode = int(getattr(owned_call, "opcode", -1))
            owned_call_destination = getattr(owned_call, "d", None)
            owned_call_native_origin = (
                f"0x{owned_call_ea:X}"
                if identity is not None
                and owned_call_ea in identity.exact_instruction_eas
                else "unmapped"
            )
            owned_call_diagnostic = (
                f"owned_call_ea=0x{owned_call_ea:X} "
                f"owned_call_native_origin={owned_call_native_origin} "
                f"owned_call_opcode="
                f"{opcode_name(owned_call_opcode) or 'unknown'}"
                f"({owned_call_opcode}) "
                "owned_call_dest_type="
                + (
                    "none"
                    if owned_call_destination is None
                    else str(int(getattr(owned_call_destination, "t", -1)))
                )
            )
        return (
            f"operation={operation.description!r} "
            f"stable_identity={stable_identity} "
            f"live={self._semantic_edge_block_label(source)} "
            f"block_type={int(getattr(source, 'type', -1))} "
            f"nsucc={int(source.nsucc())} "
            f"successors=[{','.join(successors)}] "
            f"{tail_diagnostic} "
            f"{owned_call_diagnostic} "
            "expected=zero-way block-closing m_call or m_icall owner"
        )

    def _semantic_edge_close_owned_call_before_continuation(
        self,
        *,
        source_binding: object,
        source: object,
        target_binding: object,
    ) -> bool:
        """Split one CALLS-built staged block at its exact analyzed call."""
        gateway = self._mutation_gateway
        proxy = (
            None
            if gateway is None
            else gateway.identity_index.logical_proxy_for_handle(source_binding.handle)
        )
        source_version = (
            None
            if proxy is None
            else proxy.resolve(transaction_id=self._semantic_fragment_transaction_id())
        )
        tail = getattr(source, "tail", None)
        if (
            source_version is None
            or source_version.handle != source_binding.handle
            or (
                source_version.predecessor_version_id is None
                and source_version.handle.provenance
                is not BlockHandleProvenance.IMPORTED_NATIVE
            )
            or int(source.nsucc()) != 0
            or int(getattr(source, "type", -1)) != int(ida_hexrays.BLT_1WAY)
            or tail is None
            or int(getattr(tail, "opcode", -1)) != int(ida_hexrays.m_goto)
        ):
            return False

        instructions = self._block_instructions(source)
        call_owners = tuple(
            (index, instruction, owned_call)
            for index, instruction in enumerate(instructions)
            if (owned_call := sdk_owned_call(instruction)) is not None
        )
        if not call_owners:
            return False
        if len(call_owners) != 1:
            raise SemanticEdgeOperationRejected(
                "CALLS-built fallthrough source has ambiguous analyzed call ownership"
            )
        call_index, _call_owner, call = call_owners[0]
        call_destination = getattr(call, "d", None)
        if call_destination is None or int(getattr(call_destination, "t", -1)) != int(
            ida_hexrays.mop_f
        ):
            raise SemanticEdgeOperationRejected(
                "CALLS-built fallthrough source call lacks analyzed authority"
            )

        source_identity = source_binding.handle.stable_identity
        target_identity = target_binding.handle.stable_identity
        if source_identity is None or target_identity is None:
            raise SemanticEdgeOperationRejected(
                "CALLS-built fallthrough split lacks portable identity authority"
            )
        call_native_ea = int(self.mba.map_fict_ea(int(call.ea)))
        if call_native_ea not in source_identity.exact_instruction_eas:
            raise SemanticEdgeOperationRejected(
                "CALLS-built fallthrough call is not exactly owned by its source; "
                f"call=0x{call_native_ea:X}"
            )

        suffix = instructions[call_index + 1 :]
        if (
            not suffix
            or getattr(suffix[-1], "next", None) is not None
            or int(getattr(suffix[-1], "opcode", -1)) != int(ida_hexrays.m_goto)
        ):
            raise SemanticEdgeOperationRejected(
                "CALLS-built fallthrough source lacks one final stale goto suffix"
            )
        for index, instruction in enumerate(suffix):
            opcode = int(instruction.opcode)
            if index == len(suffix) - 1:
                continue
            native_ea = int(self.mba.map_fict_ea(int(instruction.ea)))
            if (
                not target_identity.native_ranges.contains(native_ea)
                or ida_hexrays.is_mcode_jcond(opcode)
                or opcode
                in {
                    int(ida_hexrays.m_goto),
                    int(ida_hexrays.m_ijmp),
                    int(ida_hexrays.m_call),
                    int(ida_hexrays.m_icall),
                    int(ida_hexrays.m_ret),
                }
                or sdk_owned_call(instruction) is not None
            ):
                raise SemanticEdgeOperationRejected(
                    "CALLS-built fallthrough suffix is not wholly owned by its "
                    f"continuation; instruction=0x{native_ea:X} opcode={opcode}"
                )

        for instruction in suffix:
            source.make_nop(instruction)
            source.remove_from_block(instruction)
        source.type = int(ida_hexrays.BLT_0WAY)
        source.flags &= ~int(ida_hexrays.MBL_GOTO)
        source.mark_lists_dirty()
        self.mba.mark_chains_dirty()
        return sdk_owned_call(source.tail) is not None

    def _semantic_edge_live_binding(self, proxy):
        gateway = self._mutation_gateway
        if gateway is None or not gateway.active:
            raise RuntimeError(
                "semantic edge realization requires an active mutation gateway"
            )
        binding = gateway.resolve_logical_proxy(proxy)
        if binding is None:
            raise SemanticEdgeOperationRejected(
                f"logical proxy {proxy.proxy_token} has no transaction-local version"
            )
        block = self.mba.get_mblock(int(binding.serial))
        if block is None:
            raise SemanticEdgeOperationRejected(
                f"logical proxy {proxy.proxy_token} has no live MBA block"
            )
        return binding, block

    def _semantic_edge_conditional_arms(self, source):
        label = self._semantic_edge_block_label(source)
        tail = source.tail
        if (
            int(source.nsucc()) != 2
            or tail is None
            or not _is_redirectable_conditional_tail(tail)
            or getattr(tail, "d", None) is None
            or int(tail.d.t) != int(ida_hexrays.mop_b)
        ):
            raise SemanticEdgeOperationRejected(
                f"semantic conditional role requires a two-way conditional at {label}"
            )
        taken_serial = int(tail.d.b)
        successors = tuple(int(successor) for successor in source.succset)
        fallthroughs = tuple(
            successor for successor in successors if successor != taken_serial
        )
        if taken_serial not in successors or len(fallthroughs) != 1:
            raise SemanticEdgeOperationRejected(
                f"conditional arm topology is inconsistent at {label}"
            )
        taken = self.mba.get_mblock(taken_serial)
        fallthrough = self.mba.get_mblock(fallthroughs[0])
        if taken is None or fallthrough is None:
            raise SemanticEdgeOperationRejected(
                f"conditional arm target is missing at {label}"
            )
        return taken, fallthrough

    def _semantic_edge_proxy_for_live_block(self, block):
        gateway = self._mutation_gateway
        if gateway is None:
            raise RuntimeError("semantic edge realization requires a gateway")
        handle = gateway.identity_index.handle_for_serial(int(block.serial))
        proxy = gateway.identity_index.logical_proxy_for_handle(handle)
        if proxy is None:
            raise SemanticEdgeOperationRejected(
                "conditional sibling has no logical proxy at "
                f"{self._semantic_edge_block_label(block)}"
            )
        return proxy

    def _semantic_edge_mark(self, *blocks) -> None:
        for block in blocks:
            if block is None:
                continue
            if int(block.serial) != int(self.mba.qty) - 1:
                block.mark_lists_dirty()
        self.mba.mark_chains_dirty()

    def _semantic_edge_record(self, source_binding, target_binding) -> None:
        gateway = self._mutation_gateway
        if gateway is None:
            raise RuntimeError("semantic edge realization requires a gateway")
        gateway.record_edge_redirect(
            source=source_binding.handle,
            target=target_binding.handle,
        )

    def _semantic_edge_redirect_direct(
        self,
        operation: LogicalSemanticEdgeOperation,
        edge: LogicalSemanticEdge,
    ) -> None:
        source_binding, source = self._semantic_edge_live_binding(operation.source)
        target_binding, target = self._semantic_edge_live_binding(edge.target)
        source_successors = tuple(int(value) for value in source.succset)
        if len(source_successors) == 0:
            if edge.expected_target is not None:
                raise SemanticEdgeOperationRejected(
                    "zero-way edge materialization cannot name an expected target"
                )
            tail = source.tail
            replaces_existing_transfer = tail is not None and (
                _is_redirectable_conditional_tail(tail)
                or int(tail.opcode)
                in {
                    int(ida_hexrays.m_ijmp),
                    int(ida_hexrays.m_call),
                    int(ida_hexrays.m_icall),
                }
            )
            if replaces_existing_transfer:
                if operation.rewrite_anchor_ea is None:
                    raise SemanticEdgeOperationRejected(
                        "zero-way transfer direct replacement requires an exact "
                        "rewrite anchor"
                    )
                changed = self._apply_materialize_zero_way_goto(
                    source,
                    predicate_ea=int(operation.rewrite_anchor_ea),
                    target_serial=int(target.serial),
                )
            else:
                changed = self._apply_terminal_goto_change(
                    source,
                    int(target.serial),
                    instruction_ea=operation.rewrite_anchor_ea,
                )
        elif len(source_successors) == 1:
            if edge.expected_target is None:
                raise SemanticEdgeOperationRejected(
                    "one-way redirect requires an expected target proxy"
                )
            expected_binding, _expected = self._semantic_edge_live_binding(
                edge.expected_target
            )
            if int(source_successors[0]) != int(expected_binding.serial):
                raise SemanticEdgeOperationRejected(
                    "expected direct target does not own the live edge"
                )
            changed = self._apply_goto_change(source, int(target.serial))
        else:
            raise SemanticEdgeOperationRejected(
                "direct role supports only zero-way materialization or one-way redirect at "
                f"{self._semantic_edge_block_label(source)}"
            )
        if not changed:
            raise SemanticEdgeOperationRejected(
                "Hex-Rays rejected the direct semantic edge mutation at "
                f"{self._semantic_edge_block_label(source)}"
            )
        self._semantic_edge_record(source_binding, target_binding)

    def _semantic_edge_materialize_call_fallthrough(
        self,
        operation: LogicalSemanticEdgeOperation,
        edge: LogicalSemanticEdge,
        *,
        helper_plan_ref: PlanBlockRef,
    ) -> LogicalBlockVersion:
        source_binding, source = self._semantic_edge_live_binding(operation.source)
        target_binding, target = self._semantic_edge_live_binding(edge.target)
        tail = source.tail
        if int(source.nsucc()) == 0 and sdk_owned_call(tail) is None:
            self._semantic_edge_close_owned_call_before_continuation(
                source_binding=source_binding,
                source=source,
                target_binding=target_binding,
            )
            tail = source.tail
        if int(source.nsucc()) != 0 or sdk_owned_call(tail) is None:
            raise SemanticEdgeOperationRejected(
                "call fallthrough requires a zero-way block-closing call; "
                + self._semantic_edge_call_fallthrough_diagnostic(
                    operation,
                    source_binding,
                    source,
                )
            )
        if edge.expected_target is not None:
            raise SemanticEdgeOperationRejected(
                "zero-way call fallthrough cannot name an expected target"
            )

        helper_serial, helper_version = self._stage_semantic_fallthrough_helper(
            source,
            target,
            target_handle=target_binding.handle,
            plan_ref=helper_plan_ref,
        )
        source_binding, source = self._semantic_edge_live_binding(operation.source)
        target_binding, target = self._semantic_edge_live_binding(edge.target)
        helper = self.mba.get_mblock(int(helper_serial))
        tail = source.tail
        if (
            helper is None
            or source.nextb is None
            or int(helper.serial) != int(source.serial) + 1
            or int(source.nextb.serial) != int(helper.serial)
            or int(source.nsucc()) != 0
            or sdk_owned_call(tail) is None
            or tuple(int(value) for value in helper.succset) != (int(target.serial),)
        ):
            raise SemanticEdgeOperationRejected(
                "call fallthrough helper is not one adjacent transparent successor"
            )

        source.type = int(ida_hexrays.BLT_1WAY)
        source.flags &= ~int(ida_hexrays.MBL_GOTO)
        source.succset.push_back(int(helper.serial))
        if int(source.serial) not in {int(value) for value in helper.predset}:
            helper.predset.push_back(int(source.serial))
        self._semantic_edge_mark(source, helper, target)
        self._semantic_edge_record(source_binding, target_binding)
        return helper_version

    def _semantic_edge_redirect_taken(
        self,
        operation: LogicalSemanticEdgeOperation,
        edge: LogicalSemanticEdge,
    ) -> None:
        source_binding, source = self._semantic_edge_live_binding(operation.source)
        target_binding, target = self._semantic_edge_live_binding(edge.target)
        taken, fallthrough = self._semantic_edge_conditional_arms(source)
        if edge.expected_target is None:
            raise SemanticEdgeOperationRejected(
                "conditional taken redirect requires an expected target proxy"
            )
        expected_binding, _expected = self._semantic_edge_live_binding(
            edge.expected_target
        )
        if int(taken.serial) != int(expected_binding.serial):
            raise SemanticEdgeOperationRejected(
                "expected taken target does not own the live arm"
            )
        if int(target.serial) == int(fallthrough.serial):
            raise SemanticEdgeOperationRejected(
                "conditional taken and fallthrough targets must remain distinct"
            )
        if not self._apply_target_change(
            source,
            int(target.serial),
            old_target=int(taken.serial),
        ):
            raise SemanticEdgeOperationRejected(
                "Hex-Rays rejected the conditional taken-arm mutation at "
                f"{self._semantic_edge_block_label(source)}"
            )
        self._semantic_edge_record(source_binding, target_binding)

    def _semantic_edge_redirect_fallthrough(
        self,
        operation: LogicalSemanticEdgeOperation,
        edge: LogicalSemanticEdge,
        *,
        helper_plan_ref: PlanBlockRef,
    ) -> LogicalBlockVersion:
        source_binding, source = self._semantic_edge_live_binding(operation.source)
        target_binding, target = self._semantic_edge_live_binding(edge.target)
        taken, fallthrough = self._semantic_edge_conditional_arms(source)
        if edge.expected_target is None:
            raise SemanticEdgeOperationRejected(
                "conditional fallthrough redirect requires an expected target proxy"
            )
        expected_binding, _expected = self._semantic_edge_live_binding(
            edge.expected_target
        )
        if int(fallthrough.serial) != int(expected_binding.serial):
            raise SemanticEdgeOperationRejected(
                "expected fallthrough target does not own the live arm"
            )
        if source.nextb is None or int(source.nextb.serial) != int(fallthrough.serial):
            raise SemanticEdgeOperationRejected(
                "invalid physical fallthrough topology at "
                f"{self._semantic_edge_block_label(source)}"
            )
        if int(target.serial) == int(taken.serial):
            raise SemanticEdgeOperationRejected(
                "conditional taken and fallthrough targets must remain distinct"
            )
        taken_proxy = self._semantic_edge_proxy_for_live_block(taken)
        helper_serial, helper_version = self._stage_semantic_fallthrough_helper(
            source,
            target,
            target_handle=target_binding.handle,
            plan_ref=helper_plan_ref,
        )

        source_binding, source = self._semantic_edge_live_binding(operation.source)
        target_binding, target = self._semantic_edge_live_binding(edge.target)
        expected_binding, fallthrough = self._semantic_edge_live_binding(
            edge.expected_target
        )
        _taken_binding, taken = self._semantic_edge_live_binding(taken_proxy)
        helper = self.mba.get_mblock(int(helper_serial))
        if (
            helper is None
            or source.nextb is None
            or int(helper.serial) != int(source.serial) + 1
            or int(source.nextb.serial) != int(helper.serial)
        ):
            raise SemanticEdgeOperationRejected(
                "fallthrough helper is not physically adjacent to the source"
            )
        successors = tuple(int(value) for value in source.succset)
        if (
            int(expected_binding.serial) not in successors
            or int(taken.serial) not in successors
        ):
            raise SemanticEdgeOperationRejected(
                "conditional topology changed while staging fallthrough helper"
            )

        source.succset.clear()
        source.succset.push_back(int(helper.serial))
        source.succset.push_back(int(taken.serial))
        if int(source.serial) in {int(value) for value in fallthrough.predset}:
            fallthrough.predset._del(int(source.serial))
        if int(source.serial) not in {int(value) for value in helper.predset}:
            helper.predset.push_back(int(source.serial))
        self._semantic_edge_mark(source, helper, fallthrough, taken, target)
        self._semantic_edge_record(source_binding, target_binding)
        return helper_version

    def _semantic_edge_reconstruct_conditional(
        self,
        operation: LogicalSemanticEdgeOperation,
        *,
        helper_plan_ref: PlanBlockRef,
    ) -> LogicalBlockVersion:
        by_role = {edge.role: edge for edge in operation.edges}
        taken_edge = by_role[SemanticEdgeRole.CONDITIONAL_TAKEN]
        fallthrough_edge = by_role[SemanticEdgeRole.CONDITIONAL_FALLTHROUGH]
        source_binding, source = self._semantic_edge_live_binding(operation.source)
        taken_binding, taken = self._semantic_edge_live_binding(taken_edge.target)
        fallthrough_binding, fallthrough = self._semantic_edge_live_binding(
            fallthrough_edge.target
        )
        label = self._semantic_edge_block_label(source)
        predicate_diagnostic = self._semantic_edge_conditional_diagnostic(
            operation,
            source_binding,
            source,
        )
        tail = source.tail
        if (
            tail is None
            or not _is_redirectable_conditional_tail(tail)
            or int(tail.ea) != int(operation.predicate_anchor_ea)
        ):
            raise SemanticEdgeOperationRejected(
                "conditional reconstruction predicate does not match "
                f"{predicate_diagnostic}"
            )
        if int(source.nsucc()) not in {0, 2}:
            raise SemanticEdgeOperationRejected(
                f"conditional reconstruction requires zero-way or two-way source at {label}"
            )
        if int(taken.serial) == int(fallthrough.serial):
            raise SemanticEdgeOperationRejected(
                "conditional reconstruction targets must be distinct"
            )

        old_proxies = ()
        if int(source.nsucc()) == 0:
            if (
                taken_edge.expected_target is not None
                or fallthrough_edge.expected_target is not None
            ):
                raise SemanticEdgeOperationRejected(
                    "zero-way conditional reconstruction cannot name old arms"
                )
        else:
            old_taken, old_fallthrough = self._semantic_edge_conditional_arms(source)
            if (
                taken_edge.expected_target is None
                or fallthrough_edge.expected_target is None
            ):
                raise SemanticEdgeOperationRejected(
                    "two-way conditional reconstruction requires both expected arms"
                )
            expected_taken_binding, _ = self._semantic_edge_live_binding(
                taken_edge.expected_target
            )
            expected_fallthrough_binding, _ = self._semantic_edge_live_binding(
                fallthrough_edge.expected_target
            )
            if int(old_taken.serial) != int(expected_taken_binding.serial) or int(
                old_fallthrough.serial
            ) != int(expected_fallthrough_binding.serial):
                raise SemanticEdgeOperationRejected(
                    "conditional reconstruction expected arms are stale"
                )
            if source.nextb is None or int(source.nextb.serial) != int(
                old_fallthrough.serial
            ):
                raise SemanticEdgeOperationRejected(
                    f"invalid physical fallthrough topology at {label}"
                )
            old_proxies = (
                taken_edge.expected_target,
                fallthrough_edge.expected_target,
            )

        helper_serial, helper_version = self._stage_semantic_fallthrough_helper(
            source,
            fallthrough,
            target_handle=fallthrough_binding.handle,
            plan_ref=helper_plan_ref,
        )
        source_binding, source = self._semantic_edge_live_binding(operation.source)
        taken_binding, taken = self._semantic_edge_live_binding(taken_edge.target)
        fallthrough_binding, fallthrough = self._semantic_edge_live_binding(
            fallthrough_edge.target
        )
        old_blocks = tuple(
            self._semantic_edge_live_binding(proxy)[1] for proxy in old_proxies
        )
        helper = self.mba.get_mblock(int(helper_serial))
        if (
            helper is None
            or source.nextb is None
            or int(helper.serial) != int(source.serial) + 1
            or int(source.nextb.serial) != int(helper.serial)
        ):
            raise SemanticEdgeOperationRejected(
                "fallthrough helper is not physically adjacent to the source"
            )
        tail = source.tail
        if (
            tail is None
            or not _is_redirectable_conditional_tail(tail)
            or int(tail.ea) != int(operation.predicate_anchor_ea)
        ):
            raise SemanticEdgeOperationRejected(
                "conditional predicate changed while staging its destinations; "
                + self._semantic_edge_conditional_diagnostic(
                    operation,
                    source_binding,
                    source,
                )
            )

        for old_block in old_blocks:
            if int(source.serial) in {int(value) for value in old_block.predset}:
                old_block.predset._del(int(source.serial))
        source.succset.clear()
        source.succset.push_back(int(helper.serial))
        source.succset.push_back(int(taken.serial))
        tail.d.erase()
        tail.d.make_blkref(int(taken.serial))
        source.type = int(ida_hexrays.BLT_2WAY)
        source.flags &= ~int(ida_hexrays.MBL_GOTO)
        if int(source.serial) not in {int(value) for value in helper.predset}:
            helper.predset.push_back(int(source.serial))
        if int(source.serial) not in {int(value) for value in taken.predset}:
            taken.predset.push_back(int(source.serial))
        self._semantic_edge_mark(
            source,
            helper,
            taken,
            fallthrough,
            *old_blocks,
        )
        self._semantic_edge_record(source_binding, taken_binding)
        self._semantic_edge_record(source_binding, fallthrough_binding)
        return helper_version

    def _realize_semantic_edge_operation(
        self,
        operation: LogicalSemanticEdgeOperation,
        *,
        helper_plan_ref: PlanBlockRef | None = None,
    ) -> LogicalBlockVersion | None:
        """Backend-only role dispatcher for the gateway operation.

        This is intentionally not a queue API.  Callers submit one logical
        operation to :class:`MbaMutationGateway`; only the gateway invokes this
        method inside the owning transaction.
        """
        if not isinstance(operation, LogicalSemanticEdgeOperation):
            raise TypeError("semantic edge backend requires a logical operation")
        self._pending_semantic_helper_version = None
        result: LogicalBlockVersion | None = None
        try:
            if len(operation.edges) == 2:
                if helper_plan_ref is None:
                    raise SemanticEdgeOperationRejected(
                        "conditional reconstruction requires PlanBlockRef helper authority"
                    )
                result = self._semantic_edge_reconstruct_conditional(
                    operation,
                    helper_plan_ref=helper_plan_ref,
                )
            else:
                edge = operation.edges[0]
                if edge.role is SemanticEdgeRole.DIRECT:
                    self._semantic_edge_redirect_direct(operation, edge)
                elif edge.role is SemanticEdgeRole.CALL_FALLTHROUGH:
                    if helper_plan_ref is None:
                        raise SemanticEdgeOperationRejected(
                            "call fallthrough requires PlanBlockRef helper authority"
                        )
                    result = self._semantic_edge_materialize_call_fallthrough(
                        operation,
                        edge,
                        helper_plan_ref=helper_plan_ref,
                    )
                elif edge.role is SemanticEdgeRole.CONDITIONAL_TAKEN:
                    self._semantic_edge_redirect_taken(operation, edge)
                elif edge.role is SemanticEdgeRole.CONDITIONAL_FALLTHROUGH:
                    if helper_plan_ref is None:
                        raise SemanticEdgeOperationRejected(
                            "conditional fallthrough requires PlanBlockRef helper authority"
                        )
                    result = self._semantic_edge_redirect_fallthrough(
                        operation,
                        edge,
                        helper_plan_ref=helper_plan_ref,
                    )
                else:
                    raise SemanticEdgeOperationRejected(
                        f"unsupported semantic edge role: {edge.role!r}"
                    )
        except Exception:
            pending = self._pending_semantic_helper_version
            self._pending_semantic_helper_version = None
            gateway = self._mutation_gateway
            if pending is not None and (
                gateway is None or not gateway.mutation_started
            ):
                self._discard_detached_semantic_versions((pending,))
            raise
        self._pending_semantic_helper_version = None
        return result

    def _snapshot_semantic_fragment_inputs(self, plan: FragmentPlan):
        """Backend-only immutable preflight snapshot port."""
        return snapshot_semantic_fragment_inputs(self, plan)

    def _generated_semantic_fragment_plan_handle(
        self,
        plan: FragmentPlan,
        block_id: str,
    ):
        """Return one graph-free plan handle without exposing SDK coordinates."""
        from d810.hexrays.mutation.semantic_fragment_backend import (
            generated_plan_live_bindings,
        )

        live = generated_plan_live_bindings(self, plan).get(str(block_id))
        gateway = self._mutation_gateway
        if live is None or gateway is None:
            raise SemanticFragmentBackendRejected(
                f"GENERATED plan block {block_id!r} has no live binding"
            )
        handle = gateway.identity_index.handle_for_serial(int(live.serial))
        if handle is None:
            raise SemanticFragmentBackendRejected(
                f"GENERATED plan block {block_id!r} has no identity handle"
            )
        return handle

    def _realize_semantic_patch_plan(
        self,
        patch_plan,
        prepared_fragment: PreparedSemanticFragment,
    ):
        """Execute typed semantic PatchSteps under this gateway."""
        return realize_semantic_patch_plan(self, patch_plan, prepared_fragment)

    def _observe_staged_semantic_fragment(self, plan: FragmentPlan):
        """Backend-only live observation of an unpublished fragment."""
        return observe_staged_semantic_fragment(self, plan)

    def _semantic_fragment_transaction_id(self) -> str:
        gateway = self._mutation_gateway
        if gateway is None or not gateway.active:
            raise SemanticFragmentBackendRejected(
                "semantic fragment materialization requires an active gateway"
            )
        batch_id = gateway.active_batch_id
        if batch_id is None:
            raise SemanticFragmentBackendRejected(
                "semantic fragment materialization has no active transaction id"
            )
        return batch_id

    def _resolve_semantic_fragment_version(
        self,
        version: LogicalBlockVersion,
    ):
        gateway = self._mutation_gateway
        if gateway is None:
            raise SemanticFragmentBackendRejected(
                "semantic fragment materialization has no gateway"
            )
        binding = gateway.identity_index.resolve_logical_version(
            version,
            transaction_id=self._semantic_fragment_transaction_id(),
        )
        if binding is None:
            raise SemanticFragmentBackendRejected(
                "semantic fragment logical version has no live transaction binding"
            )
        block = self.mba.get_mblock(int(binding.serial))
        if block is None:
            raise SemanticFragmentBackendRejected(
                "semantic fragment logical version is absent from the live MBA"
            )
        return block

    def _detach_semantic_fragment_block(self, block) -> None:
        """Detach one unpublished block without exposing a publication root."""
        block_serial = int(block.serial)
        for successor_serial in tuple(int(value) for value in block.succset):
            successor = self.mba.get_mblock(successor_serial)
            if successor is not None:
                successor.predset._del(block_serial)
                # BLT_STOP is instructionless, so changing only predecessor
                # metadata does not invalidate its block-local use/def lists.
                # Once callinfo is built, Hex-Rays requires the lists produced
                # by refine_return_type to remain ready (verify.cpp INTERR
                # 51328).
                if int(successor.type) != int(ida_hexrays.BLT_STOP):
                    successor.mark_lists_dirty()
        for predecessor_serial in tuple(int(value) for value in block.predset):
            predecessor = self.mba.get_mblock(predecessor_serial)
            if predecessor is not None:
                predecessor.succset._del(block_serial)
                predecessor.mark_lists_dirty()
        block.succset.clear()
        block.predset.clear()
        block.mark_lists_dirty()
        self.mba.mark_chains_dirty()

    def _discard_semantic_fragment_blocks(self, blocks: tuple[object, ...]) -> None:
        gateway = self._mutation_gateway
        if gateway is None:
            raise SemanticFragmentBackendRejected(
                "staged semantic fragment discard requires a mutation gateway"
            )
        unreachable_sweeper = getattr(
            self.mba,
            "remove_empty_and_unreachable_blocks",
            None,
        )
        if not callable(unreachable_sweeper):
            raise SemanticFragmentBackendRejected(
                "live MBA cannot sweep staged semantic fragment blocks"
            )
        blocks_by_serial = {int(block.serial): block for block in blocks}
        serials = tuple(sorted(blocks_by_serial))
        original_qty = int(self.mba.qty)
        if any(serial <= 0 or serial >= original_qty - 1 for serial in serials):
            raise SemanticFragmentBackendRejected(
                "staged semantic fragment discard cannot remove entry or stop blocks"
            )
        tail_fallthrough_restore = None
        if serials:
            first_staged_serial = int(serials[0])
            staged_tail_band = tuple(range(first_staged_serial, original_qty - 1))
            predecessor = self.mba.get_mblock(first_staged_serial - 1)
            stop = self.mba.get_mblock(original_qty - 1)
            predecessor_tail = None if predecessor is None else predecessor.tail
            predecessor_successors = (
                ()
                if predecessor is None
                else tuple(int(value) for value in predecessor.succset)
            )
            predecessor_label = (
                "missing"
                if predecessor is None
                else f"blk{int(predecessor.serial)}@0x{int(predecessor.start):X}"
            )
            successor_labels = tuple(
                (
                    f"blk{successor_serial}@0x{int(successor.start):X}"
                    if (successor := self.mba.get_mblock(successor_serial)) is not None
                    else f"missing@0x{successor_serial:X}"
                )
                for successor_serial in predecessor_successors
            )
            stop_label = (
                "missing"
                if stop is None
                else f"blk{int(stop.serial)}@0x{int(stop.start):X}"
            )
            logger.debug(
                "staged semantic rollback tail preflight: first=%s "
                "count=%d contiguous=%s predecessor=%s type=%s succs=%s "
                "tail_opcode=%s stop=%s stop_type=%s",
                (
                    "none"
                    if not serials
                    else f"blk{first_staged_serial}@0x{int(blocks_by_serial[first_staged_serial].start):X}"
                ),
                len(serials),
                serials == staged_tail_band,
                predecessor_label,
                None if predecessor is None else int(predecessor.type),
                successor_labels,
                None if predecessor_tail is None else int(predecessor_tail.opcode),
                stop_label,
                None if stop is None else int(stop.type),
            )
            if (
                serials == staged_tail_band
                and predecessor is not None
                and stop is not None
                and int(predecessor.type) == int(ida_hexrays.BLT_1WAY)
                and predecessor_successors
                in {(), (first_staged_serial,), (original_qty - 1,)}
                and predecessor_tail is not None
                and int(predecessor_tail.opcode) != int(ida_hexrays.m_goto)
                and int(stop.type) == int(ida_hexrays.BLT_STOP)
            ):
                tail_fallthrough_restore = (predecessor, stop)
        pre_sweep_index = MbaBlockIdentityIndex.from_mba(
            self.mba,
            generation=int(gateway.generation),
            native_key=gateway.native_key,
            evidence_generation=int(gateway.identity_index.evidence_generation),
            session_id=f"{gateway.session_id}:rollback-pre",
        )
        survivor_identities = {
            serial: pre_sweep_index.identity_for_serial(serial)
            for serial in range(1, original_qty - 1)
            if serial not in blocks_by_serial
        }
        survivor_identity_counts = {
            identity: tuple(
                serial
                for serial, candidate_identity in survivor_identities.items()
                if candidate_identity == identity
            )
            for identity in set(survivor_identities.values())
            if identity is not None
        }
        temporary_protections: list[tuple[int, str]] = []
        unsafe_survivors = []
        for serial, identity in survivor_identities.items():
            candidate = self.mba.get_mblock(serial)
            if candidate is None or int(candidate.flags) & int(ida_hexrays.MBL_KEEP):
                continue
            label = f"blk{serial}@0x{int(getattr(candidate, 'start', -1)):X}"
            if identity is None or len(survivor_identity_counts.get(identity, ())) != 1:
                unsafe_survivors.append(label)
                continue
            temporary_protections.append((serial, label))
        if unsafe_survivors:
            raise SemanticFragmentBackendRejected(
                "staged semantic fragment discard cannot protect and rebind "
                "survivors without unique native identity: "
                + ", ".join(unsafe_survivors)
            )
        for serial, _label in temporary_protections:
            survivor = self.mba.get_mblock(serial)
            if survivor is None:
                raise SemanticFragmentBackendRejected(
                    "staged semantic fragment survivor disappeared before sweep"
                )
            survivor.flags |= int(ida_hexrays.MBL_KEEP)
        for block in blocks_by_serial.values():
            self._detach_semantic_fragment_block(block)
            block.flags &= ~int(ida_hexrays.MBL_KEEP)
        if serials:
            changed = bool(unreachable_sweeper())
            expected_qty = original_qty - len(serials)
            if not changed or int(self.mba.qty) != expected_qty:
                raise SemanticFragmentBackendRejected(
                    "staged semantic fragment sweep removed an unexpected "
                    f"inventory: expected_qty={expected_qty} "
                    f"observed_qty={int(self.mba.qty)} changed={changed}"
                )
            if tail_fallthrough_restore is not None:
                predecessor, _prior_stop = tail_fallthrough_restore
                expected_stop_serial = expected_qty - 1
                stop = self.mba.get_mblock(expected_stop_serial)
                next_block = predecessor.nextb
                predecessor_successors = tuple(
                    int(value) for value in predecessor.succset
                )
                if (
                    int(predecessor.serial) != expected_stop_serial - 1
                    or next_block is None
                    or int(next_block.serial) != expected_stop_serial
                    or stop is None
                    or int(stop.type) != int(ida_hexrays.BLT_STOP)
                    or predecessor_successors not in {(), (expected_stop_serial,)}
                ):
                    raise SemanticFragmentBackendRejected(
                        "staged semantic fragment sweep cannot restore its exact "
                        "published tail fallthrough"
                    )
                if not predecessor_successors:
                    predecessor.succset.push_back(expected_stop_serial)
                if int(predecessor.serial) not in tuple(
                    int(value) for value in stop.predset
                ):
                    stop.predset.push_back(int(predecessor.serial))
                predecessor.mark_lists_dirty()
                # The BLT_STOP block is instructionless, so restoring its
                # predecessor metadata does not invalidate block-local
                # use/def lists.  Once callinfo is built Hex-Rays requires
                # those refine_return_type lists to remain ready (verify.cpp
                # INTERR 51328), and mark_lists_dirty() would destroy them.
            restore_failures = []
            for original_serial, label in temporary_protections:
                # Every survivor was protected and every staged block was
                # unprotected, while the exact quantity check above proves the
                # sweep removed only ``serials``.  Hex-Rays compacts the
                # remaining order, so this transaction-local coordinate is
                # stronger than rebinding a content identity after the sweep
                # has normalized survivor instructions.
                compacted_serial = int(original_serial) - sum(
                    int(removed_serial) < int(original_serial)
                    for removed_serial in serials
                )
                survivor = self.mba.get_mblock(compacted_serial)
                if survivor is None:
                    restore_failures.append(label)
                    continue
                survivor.flags &= ~int(ida_hexrays.MBL_KEEP)
            if restore_failures:
                raise SemanticFragmentBackendRejected(
                    "staged semantic fragment sweep could not restore "
                    "temporary survivor protection: " + ", ".join(restore_failures)
                )
            self.mba.mark_chains_dirty()
            safe_verify(
                self.mba,
                "staged semantic fragment rollback sweep",
            )

    def _stage_detached_semantic_replacement(
        self,
        *,
        original_version: LogicalBlockVersion,
        plan_ref: PlanBlockRef,
    ) -> LogicalBlockVersion:
        """Clone and detach one replacement behind its logical proxy."""
        gateway = self._mutation_gateway
        if gateway is None:
            raise SemanticFragmentBackendRejected(
                "semantic fragment materialization has no gateway"
            )
        original = self._resolve_semantic_fragment_version(original_version)
        if int(original.serial) == 0:
            raise SemanticFragmentBackendRejected(
                "semantic fragment cannot clone the positional entry block"
            )
        if int(original.type) in {
            int(ida_hexrays.BLT_STOP),
            int(ida_hexrays.BLT_XTRN),
        }:
            raise SemanticFragmentBackendRejected(
                "semantic fragment cannot clone a special Hex-Rays block"
            )

        attempt = gateway.current_transaction_attempt
        if attempt is None:
            raise SemanticFragmentBackendRejected(
                "semantic clone creation has no transaction attempt"
            )
        replacement_handle = gateway.identity_index.create_native_handle(
            original_version.handle.stable_identity,
            provenance=original_version.handle.provenance,
        )
        gateway.reserve_plan_block(
            attempt,
            plan_ref,
            handle=replacement_handle,
            replaces=original_version.handle,
        )
        if gateway.current_transaction_attempt is not None:
            gateway._record_fragment_mutation_started()
        clone = copy_block_keep(self.mba, original, int(self.mba.qty) - 1)
        if clone is None:
            raise SemanticFragmentBackendRejected(
                "Hex-Rays could not clone semantic fragment block"
            )
        try:
            receipt = gateway.bind_reserved_plan_block(
                attempt,
                plan_ref,
                insertion_serial=int(clone.serial),
                returned_serial=int(clone.serial),
            )
            self._detach_semantic_fragment_block(clone)
            return receipt.logical_version
        except Exception:
            if not gateway.mutation_started:
                self._discard_semantic_fragment_blocks((clone,))
            raise

    def _stage_empty_semantic_block(
        self,
        *,
        reference_version: LogicalBlockVersion,
        plan_ref: PlanBlockRef,
    ) -> LogicalBlockVersion:
        """Create one detached zero-way block with a new synthetic lineage."""
        gateway = self._mutation_gateway
        if gateway is None:
            raise SemanticFragmentBackendRejected(
                "semantic fragment materialization has no gateway"
            )
        reference = self._resolve_semantic_fragment_version(reference_version)
        attempt = gateway.current_transaction_attempt
        if attempt is None:
            raise SemanticFragmentBackendRejected(
                "semantic fragment creation has no transaction attempt"
            )
        gateway.reserve_plan_block(attempt, plan_ref)
        gateway._record_fragment_mutation_started()
        created = create_standalone_block(
            ref_blk=reference,
            blk_ins=[],
            is_0_way=True,
            verify=False,
        )
        if created is None:
            raise SemanticFragmentBackendRejected(
                "Hex-Rays could not create an empty semantic fragment block"
            )
        try:
            receipt = gateway.bind_reserved_plan_block(
                attempt,
                plan_ref,
                insertion_serial=int(created.serial),
                returned_serial=int(created.serial),
            )
            created_handle = receipt.logical_version.handle
            proxy = gateway.identity_index.logical_proxy_for_handle(created_handle)
            if proxy is None:
                raise SemanticFragmentBackendRejected(
                    "empty semantic fragment block has no logical proxy"
                )
            staged = receipt.logical_version
            if staged is None:
                raise SemanticFragmentBackendRejected(
                    "empty semantic fragment block has no staged version"
                )
            return staged
        except Exception:
            if not gateway.mutation_started:
                self._discard_semantic_fragment_blocks((created,))
            raise

    def _stage_imported_native_semantic_block(
        self,
        *,
        reference_version: LogicalBlockVersion,
        stable_identity: StableBlockIdentity,
        plan_ref: PlanBlockRef,
    ) -> LogicalBlockVersion:
        """Create one unpublished block with exact imported-native identity."""
        gateway = self._mutation_gateway
        if gateway is None:
            raise SemanticFragmentBackendRejected(
                "native body materialization has no mutation gateway"
            )
        if stable_identity.native_key != gateway.native_key:
            raise SemanticFragmentBackendRejected(
                "native body block identity belongs to another native key"
            )
        reference = self._resolve_semantic_fragment_version(reference_version)
        attempt = gateway.current_transaction_attempt
        if attempt is None:
            raise SemanticFragmentBackendRejected(
                "native body creation has no transaction attempt"
            )
        created_handle = gateway.identity_index.create_imported_native_handle(
            stable_identity
        )
        gateway.reserve_plan_block(
            attempt,
            plan_ref,
            handle=created_handle,
        )
        gateway._record_fragment_mutation_started()
        if self.semantic_fragment_publication_profile.graph_free:
            created = self.mba.insert_block(int(self.mba.qty) - 1)
            if created is not None:
                created.start = int(self.mba.entry_ea)
                created.end = int(self.mba.entry_ea) + 1
                created.type = int(ida_hexrays.BLT_NONE)
                created.flags |= int(ida_hexrays.MBL_KEEP) | int(ida_hexrays.MBL_FAKE)
        else:
            created = create_standalone_block(
                ref_blk=reference,
                blk_ins=[],
                is_0_way=True,
                verify=False,
            )
        if created is None:
            raise SemanticFragmentBackendRejected(
                "Hex-Rays could not create an imported native-body block"
            )
        recorded = False
        try:
            staged_initializers = self._block_instructions(created)
            if any(
                int(instruction.opcode) != int(ida_hexrays.m_nop)
                for instruction in staged_initializers
            ):
                raise SemanticFragmentBackendRejected(
                    "imported native-body block inherited a non-placeholder instruction"
                )
            self.remove_nops_now(created)
            if created.head is not None or created.tail is not None:
                raise SemanticFragmentBackendRejected(
                    "imported native-body placeholder removal was incomplete"
                )
            receipt = gateway.bind_reserved_plan_block(
                attempt,
                plan_ref,
                insertion_serial=int(created.serial),
                returned_serial=int(created.serial),
            )
            recorded = True
            proxy = gateway.identity_index.logical_proxy_for_handle(created_handle)
            if proxy is None:
                raise SemanticFragmentBackendRejected(
                    "imported native-body block has no logical proxy"
                )
            staged = receipt.logical_version
            if staged is None:
                raise SemanticFragmentBackendRejected(
                    "imported native-body block has no staged version"
                )
            if not self.semantic_fragment_publication_profile.graph_free:
                self._detach_semantic_fragment_block(created)
            return staged
        except Exception:
            if not gateway.mutation_started:
                if recorded and created_handle is not None:
                    gateway.discard_reserved_insert(created_handle)
                self._discard_semantic_fragment_blocks((created,))
            raise

    def _populate_imported_native_semantic_block(
        self,
        *,
        version: LogicalBlockVersion,
        instructions: tuple[tuple[int, object], ...],
        block_flags: int,
    ) -> tuple[tuple[int, int], ...]:
        """Populate one unpublished imported block behind the gateway boundary."""
        if version.handle.provenance is not BlockHandleProvenance.IMPORTED_NATIVE:
            raise SemanticFragmentBackendRejected(
                "native body population requires imported-native provenance"
            )
        block = self._resolve_semantic_fragment_version(version)
        if (
            block.head is not None
            or block.tail is not None
            or int(block.nsucc()) != 0
            or int(block.npred()) != 0
        ):
            raise SemanticFragmentBackendRejected(
                "PREOPT native body block was not staged empty"
            )

        origin_bindings: list[tuple[int, int]] = []
        for native_ea, instruction in instructions:
            native_ea = int(native_ea)
            if getattr(instruction, "next", None) is not None:
                raise SemanticFragmentBackendRejected(
                    "PREOPT native body instruction is already linked"
                )
            live_ea = int(self.mba.alloc_fict_ea(native_ea))
            instruction.setaddr(live_ea)
            self.insert_instruction_now(
                block,
                instruction,
                block.tail,
            )
            origin_bindings.append((live_ea, native_ea))

        self.configure_block_now(
            block,
            block_type=int(
                ida_hexrays.BLT_NONE
                if self.semantic_fragment_publication_profile.graph_free
                else ida_hexrays.BLT_0WAY
            ),
            flags=(int(block_flags) & int(ida_hexrays.MBL_PUSH))
            | int(ida_hexrays.MBL_KEEP)
            | int(ida_hexrays.MBL_FAKE)
            | (
                int(ida_hexrays.MBL_PROP)
                if self.semantic_fragment_publication_profile.graph_free
                else 0
            ),
            start_ea=int(self.mba.entry_ea),
            end_ea=int(self.mba.entry_ea) + 1,
        )
        if not self.semantic_fragment_publication_profile.graph_free:
            self.mark_blocks_dirty_now(block)
        return tuple(origin_bindings)

    def _bind_prepared_imported_direct_transfer(
        self,
        *,
        source_version: LogicalBlockVersion,
        target_version: LogicalBlockVersion,
        rewrite_anchor_ea: int,
    ) -> None:
        """Wire one prepared direct terminator before its fragment is published."""
        if (
            source_version.handle.provenance
            is not BlockHandleProvenance.IMPORTED_NATIVE
        ):
            raise SemanticFragmentBackendRejected(
                "prepared direct transfer requires imported-native source provenance"
            )
        source = self._resolve_semantic_fragment_version(source_version)
        target = self._resolve_semantic_fragment_version(target_version)
        tail = source.tail
        if (
            tail is None
            or int(source.nsucc()) != 0
            or int(tail.ea) != int(rewrite_anchor_ea)
            or int(tail.opcode) != int(ida_hexrays.m_goto)
        ):
            raise SemanticFragmentBackendRejected(
                "prepared direct transfer no longer owns its unpublished "
                f"terminator at 0x{int(rewrite_anchor_ea):X}"
            )
        gateway = self._mutation_gateway
        if gateway is None or not gateway.active:
            raise SemanticFragmentBackendRejected(
                "prepared direct transfer lost its active mutation gateway"
            )
        if self.semantic_fragment_publication_profile.graph_free:
            tail.l.make_blkref(int(target.serial))
            source.type = int(ida_hexrays.BLT_NONE)
            source.flags |= int(ida_hexrays.MBL_PROP)
        elif not self._apply_terminal_goto_change(source, int(target.serial)):
            raise SemanticFragmentBackendRejected(
                "Hex-Rays rejected prepared direct transfer binding at "
                f"0x{int(rewrite_anchor_ea):X}"
            )
        gateway.record_edge_redirect(
            source=source_version.handle,
            target=target_version.handle,
        )

    def _stage_semantic_fallthrough_helper(
        self,
        source,
        target,
        *,
        target_handle: MbaBlockHandle,
        plan_ref: PlanBlockRef,
    ) -> tuple[int, LogicalBlockVersion]:
        """Create one adjacent helper with a new transaction-local lineage."""
        gateway = self._mutation_gateway
        if gateway is None:
            raise SemanticEdgeOperationRejected(
                "semantic fallthrough helper materialization has no gateway"
            )
        attempt = gateway.current_transaction_attempt
        if attempt is None:
            raise SemanticEdgeOperationRejected(
                "semantic helper creation has no transaction attempt"
            )
        reservation = gateway.reserve_plan_block(attempt, plan_ref)
        created_handle = reservation.logical_version.handle
        expected_serial = int(source.serial) + 1
        old_qty = int(self.mba.qty)
        try:
            helper_serial = self._build_fallthrough_goto_helper(
                source,
                target,
                created_handle=created_handle,
                target_handle=target_handle,
                creation_plan_ref=plan_ref,
            )
        except Exception:
            if not gateway.mutation_started and int(self.mba.qty) == old_qty + 1:
                created = self.mba.get_mblock(expected_serial)
                if created is not None:
                    self._discard_semantic_fragment_blocks((created,))
            raise
        proxy = gateway.identity_index.logical_proxy_for_handle(created_handle)
        staged = (
            None
            if proxy is None
            else proxy.resolve(transaction_id=self._semantic_fragment_transaction_id())
        )
        if helper_serial is None or staged is None:
            if not gateway.mutation_started and int(self.mba.qty) == old_qty + 1:
                created = self.mba.get_mblock(expected_serial)
                if created is not None:
                    self._discard_semantic_fragment_blocks((created,))
            raise SemanticEdgeOperationRejected(
                "Hex-Rays could not create an owned fallthrough helper"
            )
        self._pending_semantic_helper_version = staged
        return int(helper_serial), staged

    def _discard_detached_semantic_versions(
        self,
        versions: tuple[LogicalBlockVersion, ...],
    ) -> None:
        """Discard unpublished physical versions in reverse live order."""
        blocks = tuple(
            self._resolve_semantic_fragment_version(version) for version in versions
        )
        self._discard_semantic_fragment_blocks(blocks)

    def _discard_staged_semantic_fragment(self, plan: FragmentPlan) -> None:
        """Backend-only discard port for unpublished fragment versions."""
        discard_staged_semantic_fragment(self, plan)

    def _finalize_semantic_fragment_for_commit(self, plan: FragmentPlan) -> None:
        """Make postvalidated backend-owned semantics verifier-safe."""
        finalize_semantic_fragment_for_commit(self, plan)

    def _restore_semantic_terminal_finalization_now(
        self,
        *,
        block: ida_hexrays.mblock_t,
        tail_copy: ida_hexrays.minsn_t,
        live_ea: int,
        block_type: int,
        successors: tuple[int, ...],
    ) -> None:
        """Restore one compensated terminal through the live mutation port."""
        tail = block.tail
        if tail is not None and int(tail.opcode) == int(ida_hexrays.m_ret):
            # Failure can occur during address rebinding, before the terminal
            # is removed.  Only touch the still-linked instruction then.
            tail.setaddr(int(live_ea))
        else:
            # Once canonicalization removes the owned return, append its owned
            # copy after any surviving value/prefix instructions.
            block.insert_into_block(tail_copy, tail)
        block.type = int(block_type)
        block.succset.clear()
        for serial in successors:
            block.succset.push_back(int(serial))
        block.mark_lists_dirty()

    def _restore_semantic_stop_finalization_now(
        self,
        *,
        stop: ida_hexrays.mblock_t | None,
        predecessors: tuple[int, ...],
    ) -> None:
        """Restore the canonical STOP predecessor inventory and dirty state."""
        if stop is not None:
            stop.predset.clear()
            for serial in predecessors:
                stop.predset.push_back(int(serial))
            stop.mark_lists_dirty()
        self.mba.mark_chains_dirty()

    def _semantic_fragment_current_mba_identity_binding(
        self,
        plan: FragmentPlan,
    ) -> CurrentMbaIdentityBindingSnapshot:
        """Return staged point origins and full serial-free block identities."""
        state = self._semantic_fragment_state
        if (
            state is None
            or state.plan_id != plan.plan_id
            or state.atomic_group_id != plan.atomic_group_id
        ):
            raise SemanticFragmentBackendRejected(
                "semantic fragment origins have no matching staged state"
            )
        native_by_live: dict[int, int] = {}
        block_bindings: list[CurrentMbaBlockIdentityBinding] = []
        for block_id in sorted(state.instruction_origins_by_block_id):
            origins = state.instruction_origins_by_block_id[block_id]
            if not origins:
                continue
            block = self._resolve_semantic_fragment_version(
                state.binding(block_id).version
            )
            live_instruction_eas = {
                int(instruction.ea) for instruction in self._block_instructions(block)
            }
            stale_live_eas = set(int(ea) for ea in origins) - live_instruction_eas
            if stale_live_eas:
                raise SemanticFragmentBackendRejected(
                    "semantic fragment current identity contains inactive live "
                    f"instructions: block={block_id!r} "
                    f"eas={tuple(hex(ea) for ea in sorted(stale_live_eas))!r}"
                )
            stable_identity = state.binding(block_id).version.handle.stable_identity
            if stable_identity is None:
                raise SemanticFragmentBackendRejected(
                    "semantic fragment instruction origins lack stable identity"
                )
            for live_ea, native_ea in origins.items():
                live_ea = int(live_ea)
                native_ea = int(native_ea)
                previous = native_by_live.get(live_ea)
                if previous is not None and previous != native_ea:
                    raise SemanticFragmentBackendRejected(
                        "semantic fragment live instruction has conflicting origins"
                    )
                native_by_live[live_ea] = native_ea
            block_bindings.append(
                CurrentMbaBlockIdentityBinding(
                    stable_identity=stable_identity,
                    live_instruction_eas=frozenset(int(ea) for ea in origins),
                )
            )
        return CurrentMbaIdentityBindingSnapshot(
            instruction_origins=tuple(sorted(native_by_live.items())),
            block_bindings=tuple(block_bindings),
        )

    @staticmethod
    def _semantic_fragment_publication_token(
        plan: FragmentPlan,
        token: object,
    ) -> SemanticFragmentRootPublicationToken:
        if not isinstance(token, SemanticFragmentRootPublicationToken):
            raise SemanticFragmentBackendRejected(
                "semantic fragment root publication requires its rollback token"
            )
        if (
            token.plan_id != plan.plan_id
            or token.atomic_group_id != plan.atomic_group_id
        ):
            raise SemanticFragmentBackendRejected(
                "semantic fragment rollback token does not match the plan"
            )
        return token

    def _prepare_semantic_fragment_root_publication(
        self,
        plan: FragmentPlan,
        inventory: SemanticFragmentRootInventory,
    ) -> SemanticFragmentRootPublicationToken:
        """Capture serial-free root authority before the first live rewrite."""
        return prepare_semantic_fragment_root_publication(self, plan, inventory)

    def _plan_semantic_fragment_root_publication_inventory(
        self,
        plan: FragmentPlan,
    ) -> SemanticFragmentRootInventory:
        """Plan every incoming root role before opening the transaction."""
        return plan_semantic_fragment_root_inventory(self, plan)

    def _rewrite_semantic_fragment_entry_edge(
        self,
        predecessor,
        old_target,
        new_target,
    ) -> None:
        """Rewrite the synthetic block-zero edge with symmetric bookkeeping."""
        old_serial = int(old_target.serial)
        new_serial = int(new_target.serial)
        if int(predecessor.serial) != 0:
            raise SemanticFragmentBackendRejected(
                "entry-edge publication requires the positional entry block"
            )
        if tuple(int(value) for value in predecessor.succset) != (old_serial,):
            raise SemanticFragmentBackendRejected(
                "entry root authority changed after publication preflight"
            )
        tail = predecessor.tail
        if tail is not None:
            left = getattr(tail, "l", None)
            if (
                int(tail.opcode) != int(ida_hexrays.m_goto)
                or left is None
                or int(left.t) != int(ida_hexrays.mop_b)
                or int(left.b) != old_serial
            ):
                raise SemanticFragmentBackendRejected(
                    "entry root authority has an unsupported explicit tail"
                )
            left.make_blkref(new_serial)
        predecessor.succset._del(old_serial)
        predecessor.succset.push_back(new_serial)
        old_target.predset._del(int(predecessor.serial))
        if int(predecessor.serial) not in {int(value) for value in new_target.predset}:
            new_target.predset.push_back(int(predecessor.serial))
        self._semantic_edge_mark(predecessor, old_target, new_target)

    def _rewrite_semantic_fragment_direct_root(
        self,
        edge: SemanticFragmentRootEdgeBinding,
        *,
        restore: bool,
    ) -> None:
        predecessor = self._resolve_semantic_fragment_version(edge.predecessor.version)
        original = self._resolve_semantic_fragment_version(edge.original.version)
        replacement = self._resolve_semantic_fragment_version(edge.replacement.version)
        old_target = replacement if restore else original
        new_target = original if restore else replacement
        current_successors = tuple(int(value) for value in predecessor.succset)
        if restore and current_successors == (int(new_target.serial),):
            tail = predecessor.tail
            if (
                tail is not None
                and int(tail.opcode) == int(ida_hexrays.m_goto)
                and getattr(tail, "l", None) is not None
                and int(tail.l.t) == int(ida_hexrays.mop_b)
            ):
                tail.l.make_blkref(int(new_target.serial))
            old_target.predset._del(int(predecessor.serial))
            if int(predecessor.serial) not in {
                int(value) for value in new_target.predset
            }:
                new_target.predset.push_back(int(predecessor.serial))
            self._semantic_edge_mark(predecessor, old_target, new_target)
            return
        if current_successors != (int(old_target.serial),):
            raise SemanticFragmentBackendRejected(
                "direct root authority changed after publication preflight"
            )
        if int(predecessor.serial) == 0:
            self._rewrite_semantic_fragment_entry_edge(
                predecessor,
                old_target,
                new_target,
            )
            return
        if not self._apply_goto_change(predecessor, int(new_target.serial)):
            raise SemanticFragmentBackendRejected(
                "Hex-Rays rejected direct semantic fragment root publication"
            )

    def _publish_semantic_fragment_direct_fallthrough_root(
        self,
        edge: SemanticFragmentRootEdgeBinding,
    ) -> None:
        """Publish one implicit direct fallthrough through an adjacent helper."""
        helper_binding = edge.publication_helper
        gateway = self._mutation_gateway
        if (
            edge.role is not SemanticEdgeRole.DIRECT
            or not edge.requires_helper
            or helper_binding is None
            or helper_binding.creation_ref is None
            or gateway is None
        ):
            raise SemanticFragmentBackendRejected(
                "direct fallthrough root lacks reserved helper authority"
            )
        predecessor = self._resolve_semantic_fragment_version(edge.predecessor.version)
        original = self._resolve_semantic_fragment_version(edge.original.version)
        replacement = self._resolve_semantic_fragment_version(edge.replacement.version)
        if (
            tuple(int(value) for value in predecessor.succset)
            != (int(original.serial),)
            or predecessor.nextb is None
            or int(predecessor.nextb.serial) != int(original.serial)
        ):
            raise SemanticFragmentBackendRejected(
                "direct fallthrough root authority changed after preflight"
            )
        if (
            gateway.identity_index.resolve_logical_version(
                helper_binding.version,
                transaction_id=self._semantic_fragment_transaction_id(),
            )
            is not None
        ):
            raise SemanticFragmentBackendRejected(
                "direct fallthrough root helper is already materialized"
            )

        helper_serial = self._build_fallthrough_goto_helper(
            predecessor,
            replacement,
            created_handle=helper_binding.version.handle,
            target_handle=edge.replacement.version.handle,
            creation_plan_ref=helper_binding.creation_ref,
        )
        if helper_serial is None:
            raise SemanticFragmentBackendRejected(
                "Hex-Rays could not materialize the direct root helper"
            )

        predecessor = self._resolve_semantic_fragment_version(edge.predecessor.version)
        original = self._resolve_semantic_fragment_version(edge.original.version)
        replacement = self._resolve_semantic_fragment_version(edge.replacement.version)
        helper = self._resolve_semantic_fragment_version(helper_binding.version)
        successors = tuple(int(value) for value in predecessor.succset)
        if (
            len(successors) != 1
            or successors[0] not in {int(original.serial), int(helper.serial)}
            or predecessor.nextb is None
            or int(predecessor.nextb.serial) != int(helper.serial)
            or int(helper.serial) != int(predecessor.serial) + 1
            or tuple(int(value) for value in helper.succset)
            != (int(replacement.serial),)
        ):
            raise SemanticFragmentBackendRejected(
                "direct root topology changed during helper insertion"
            )
        original.predset._del(int(predecessor.serial))
        predecessor.succset.clear()
        predecessor.succset.push_back(int(helper.serial))
        if int(predecessor.serial) not in {int(value) for value in helper.predset}:
            helper.predset.push_back(int(predecessor.serial))
        self._semantic_edge_mark(
            predecessor,
            helper,
            original,
            replacement,
        )

    def _rollback_semantic_fragment_direct_fallthrough_root(
        self,
        edge: SemanticFragmentRootEdgeBinding,
    ) -> None:
        """Restore one implicit direct fallthrough and discard its helper."""
        helper_binding = edge.publication_helper
        gateway = self._mutation_gateway
        if helper_binding is None or gateway is None:
            raise SemanticFragmentBackendRejected(
                "direct fallthrough rollback lacks helper authority"
            )
        helper_bound = gateway.identity_index.resolve_logical_version(
            helper_binding.version,
            transaction_id=self._semantic_fragment_transaction_id(),
        )
        if helper_bound is None:
            return
        predecessor = self._resolve_semantic_fragment_version(edge.predecessor.version)
        original = self._resolve_semantic_fragment_version(edge.original.version)
        replacement = self._resolve_semantic_fragment_version(edge.replacement.version)
        helper = self._resolve_semantic_fragment_version(helper_binding.version)
        successors = tuple(int(value) for value in predecessor.succset)
        if int(helper.serial) in successors:
            if successors != (int(helper.serial),):
                raise SemanticFragmentBackendRejected(
                    "direct fallthrough rollback found ambiguous live successors"
                )
            predecessor.succset.clear()
            predecessor.succset.push_back(int(original.serial))
            helper.predset._del(int(predecessor.serial))
            if int(predecessor.serial) not in {
                int(value) for value in original.predset
            }:
                original.predset.push_back(int(predecessor.serial))
            self._semantic_edge_mark(
                predecessor,
                helper,
                original,
                replacement,
            )
        elif int(original.serial) not in successors:
            raise SemanticFragmentBackendRejected(
                "direct fallthrough rollback cannot locate prior authority"
            )
        self._discard_semantic_fragment_blocks((helper,))
        gateway.discard_reserved_insert(helper_binding.version.handle)

    def _rewrite_semantic_fragment_taken_root(
        self,
        edge: SemanticFragmentRootEdgeBinding,
        *,
        restore: bool,
    ) -> None:
        predecessor = self._resolve_semantic_fragment_version(edge.predecessor.version)
        original = self._resolve_semantic_fragment_version(edge.original.version)
        replacement = self._resolve_semantic_fragment_version(edge.replacement.version)
        old_target = replacement if restore else original
        new_target = original if restore else replacement
        taken, fallthrough = self._semantic_edge_conditional_arms(predecessor)
        if restore and int(taken.serial) == int(new_target.serial):
            old_target.predset._del(int(predecessor.serial))
            if int(predecessor.serial) not in {
                int(value) for value in new_target.predset
            }:
                new_target.predset.push_back(int(predecessor.serial))
            self._semantic_edge_mark(
                predecessor,
                old_target,
                new_target,
                fallthrough,
            )
            return
        if int(taken.serial) != int(old_target.serial):
            raise SemanticFragmentBackendRejected(
                "conditional taken root authority changed after preflight"
            )
        if int(new_target.serial) == int(fallthrough.serial):
            raise SemanticFragmentBackendRejected(
                "conditional taken root cannot equal its fallthrough sibling"
            )
        if not self._apply_target_change(
            predecessor,
            int(new_target.serial),
            old_target=int(old_target.serial),
        ):
            raise SemanticFragmentBackendRejected(
                "Hex-Rays rejected conditional taken root publication"
            )

    def _publish_semantic_fragment_fallthrough_root(
        self,
        edge: SemanticFragmentRootEdgeBinding,
    ) -> None:
        helper_binding = edge.publication_helper
        if helper_binding is None:
            raise SemanticFragmentBackendRejected(
                "conditional root fallthrough has no reserved helper"
            )
        if helper_binding.creation_ref is None:
            raise SemanticFragmentBackendRejected(
                "conditional root fallthrough lacks planned helper authority"
            )
        predecessor = self._resolve_semantic_fragment_version(edge.predecessor.version)
        original = self._resolve_semantic_fragment_version(edge.original.version)
        replacement = self._resolve_semantic_fragment_version(edge.replacement.version)
        taken, fallthrough = self._semantic_edge_conditional_arms(predecessor)
        if (
            int(fallthrough.serial) != int(original.serial)
            or predecessor.nextb is None
            or int(predecessor.nextb.serial) != int(original.serial)
        ):
            raise SemanticFragmentBackendRejected(
                "conditional fallthrough root authority changed after preflight"
            )
        if int(taken.serial) == int(replacement.serial):
            raise SemanticFragmentBackendRejected(
                "conditional root replacement equals its taken sibling"
            )
        gateway = self._mutation_gateway
        if gateway is None:
            raise SemanticFragmentBackendRejected(
                "conditional root fallthrough has no mutation gateway"
            )
        if (
            gateway.identity_index.resolve_logical_version(
                helper_binding.version,
                transaction_id=self._semantic_fragment_transaction_id(),
            )
            is not None
        ):
            raise SemanticFragmentBackendRejected(
                "conditional root fallthrough helper is already materialized"
            )
        helper_serial = self._build_fallthrough_goto_helper(
            predecessor,
            replacement,
            created_handle=helper_binding.version.handle,
            target_handle=edge.replacement.version.handle,
            creation_plan_ref=helper_binding.creation_ref,
        )
        if helper_serial is None:
            raise SemanticFragmentBackendRejected(
                "Hex-Rays could not materialize the root fallthrough helper"
            )

        predecessor = self._resolve_semantic_fragment_version(edge.predecessor.version)
        original = self._resolve_semantic_fragment_version(edge.original.version)
        replacement = self._resolve_semantic_fragment_version(edge.replacement.version)
        helper = self._resolve_semantic_fragment_version(helper_binding.version)
        taken_serial = int(predecessor.tail.d.b)
        taken = self.mba.get_mblock(taken_serial)
        successors = tuple(int(value) for value in predecessor.succset)
        fallthrough_serials = tuple(
            successor for successor in successors if successor != taken_serial
        )
        if (
            taken is None
            or len(successors) != 2
            or taken_serial not in successors
            or len(fallthrough_serials) != 1
            or fallthrough_serials[0] not in {int(original.serial), int(helper.serial)}
            or predecessor.nextb is None
            or int(predecessor.nextb.serial) != int(helper.serial)
            or int(helper.serial) != int(predecessor.serial) + 1
            or tuple(int(value) for value in helper.succset)
            != (int(replacement.serial),)
        ):
            raise SemanticFragmentBackendRejected(
                "root fallthrough topology changed during helper insertion"
            )
        predecessor.succset.clear()
        predecessor.succset.push_back(int(helper.serial))
        predecessor.succset.push_back(int(taken.serial))
        original.predset._del(int(predecessor.serial))
        if int(predecessor.serial) not in {int(value) for value in helper.predset}:
            helper.predset.push_back(int(predecessor.serial))
        self._semantic_edge_mark(
            predecessor,
            helper,
            original,
            replacement,
            taken,
        )

    def _rollback_semantic_fragment_fallthrough_root(
        self,
        edge: SemanticFragmentRootEdgeBinding,
    ) -> None:
        helper_binding = edge.publication_helper
        gateway = self._mutation_gateway
        if helper_binding is None or gateway is None:
            raise SemanticFragmentBackendRejected(
                "conditional root fallthrough rollback lacks helper authority"
            )
        helper_bound = gateway.identity_index.resolve_logical_version(
            helper_binding.version,
            transaction_id=self._semantic_fragment_transaction_id(),
        )
        if helper_bound is None:
            return
        predecessor = self._resolve_semantic_fragment_version(edge.predecessor.version)
        original = self._resolve_semantic_fragment_version(edge.original.version)
        replacement = self._resolve_semantic_fragment_version(edge.replacement.version)
        helper = self._resolve_semantic_fragment_version(helper_binding.version)
        taken_serial = int(predecessor.tail.d.b)
        taken = self.mba.get_mblock(taken_serial)
        if taken is None:
            raise SemanticFragmentBackendRejected(
                "conditional root rollback lost its taken sibling"
            )
        successors = tuple(int(value) for value in predecessor.succset)
        if int(helper.serial) in successors:
            if int(original.serial) in successors or taken_serial not in successors:
                raise SemanticFragmentBackendRejected(
                    "conditional root rollback found ambiguous live successors"
                )
            predecessor.succset.clear()
            predecessor.succset.push_back(int(original.serial))
            predecessor.succset.push_back(taken_serial)
            helper.predset._del(int(predecessor.serial))
            if int(predecessor.serial) not in {
                int(value) for value in original.predset
            }:
                original.predset.push_back(int(predecessor.serial))
            self._semantic_edge_mark(
                predecessor,
                helper,
                original,
                replacement,
                taken,
            )
        elif int(original.serial) not in successors:
            raise SemanticFragmentBackendRejected(
                "conditional root rollback cannot locate prior fallthrough authority"
            )
        self._discard_semantic_fragment_blocks((helper,))
        gateway.discard_reserved_insert(helper_binding.version.handle)

    @staticmethod
    def _semantic_fragment_call_root_group_edge(
        group: SemanticFragmentRootPublicationGroup,
    ) -> SemanticFragmentRootEdgeBinding:
        if (
            not group.call_fallthrough
            or group.conditional
            or len(group.edges) != 1
            or group.edges[0].role is not SemanticEdgeRole.CALL_FALLTHROUGH
        ):
            raise SemanticFragmentBackendRejected(
                "call root group has inconsistent semantic authority"
            )
        return group.edges[0]

    def _publish_semantic_fragment_call_root_group(
        self,
        group: SemanticFragmentRootPublicationGroup,
    ) -> None:
        """Publish one call fallthrough through a gateway-owned adjacent helper."""
        edge = self._semantic_fragment_call_root_group_edge(group)
        gateway = self._mutation_gateway
        helper_binding = edge.publication_helper
        original_fallthrough_binding = group.original_fallthrough
        if (
            gateway is None
            or helper_binding is None
            or helper_binding.creation_ref is None
            or original_fallthrough_binding is None
            or group.original_call_opcode is None
            or edge.original.version is not original_fallthrough_binding.version
        ):
            raise SemanticFragmentBackendRejected(
                "call root publication lacks captured fallthrough authority"
            )

        predecessor = self._resolve_semantic_fragment_version(group.predecessor.version)
        original = self._resolve_semantic_fragment_version(
            original_fallthrough_binding.version
        )
        replacement = self._resolve_semantic_fragment_version(edge.replacement.version)
        tail = predecessor.tail
        if (
            int(predecessor.type) != int(group.original_predecessor_type)
            or int(predecessor.flags) != int(group.original_predecessor_flags)
            or tuple(int(value) for value in predecessor.succset)
            != (int(original.serial),)
            or predecessor.nextb is None
            or int(predecessor.nextb.serial) != int(original.serial)
            or tail is None
            or int(tail.opcode) != int(group.original_call_opcode)
            or int(tail.opcode)
            not in {
                int(ida_hexrays.m_call),
                int(ida_hexrays.m_icall),
            }
        ):
            raise SemanticFragmentBackendRejected(
                "call root authority changed after publication preflight"
            )
        if (
            gateway.identity_index.resolve_logical_version(
                helper_binding.version,
                transaction_id=self._semantic_fragment_transaction_id(),
            )
            is not None
        ):
            raise SemanticFragmentBackendRejected(
                "call root fallthrough helper is already materialized"
            )

        helper_serial = self._build_fallthrough_goto_helper(
            predecessor,
            replacement,
            created_handle=helper_binding.version.handle,
            target_handle=edge.replacement.version.handle,
            creation_plan_ref=helper_binding.creation_ref,
        )
        if helper_serial is None:
            raise SemanticFragmentBackendRejected(
                "Hex-Rays could not materialize the call root fallthrough helper"
            )

        predecessor = self._resolve_semantic_fragment_version(group.predecessor.version)
        original = self._resolve_semantic_fragment_version(
            original_fallthrough_binding.version
        )
        replacement = self._resolve_semantic_fragment_version(edge.replacement.version)
        helper = self._resolve_semantic_fragment_version(helper_binding.version)
        tail = predecessor.tail
        successors = tuple(int(value) for value in predecessor.succset)
        if (
            len(successors) != 1
            or successors[0] not in {int(original.serial), int(helper.serial)}
            or predecessor.nextb is None
            or int(predecessor.nextb.serial) != int(helper.serial)
            or int(helper.serial) != int(predecessor.serial) + 1
            or tuple(int(value) for value in helper.succset)
            != (int(replacement.serial),)
            or tail is None
            or int(tail.opcode) != int(group.original_call_opcode)
        ):
            raise SemanticFragmentBackendRejected(
                "call root topology changed during helper insertion"
            )

        original.predset._del(int(predecessor.serial))
        replacement.predset._del(int(predecessor.serial))
        predecessor.succset.clear()
        predecessor.succset.push_back(int(helper.serial))
        if int(predecessor.serial) not in {int(value) for value in helper.predset}:
            helper.predset.push_back(int(predecessor.serial))
        predecessor.type = int(group.original_predecessor_type)
        predecessor.flags = int(group.original_predecessor_flags)
        self._semantic_edge_mark(
            predecessor,
            helper,
            original,
            replacement,
        )

    def _rollback_semantic_fragment_call_root_group(
        self,
        group: SemanticFragmentRootPublicationGroup,
    ) -> None:
        """Restore one captured call fallthrough and remove its owned helper."""
        edge = self._semantic_fragment_call_root_group_edge(group)
        gateway = self._mutation_gateway
        helper_binding = edge.publication_helper
        original_fallthrough_binding = group.original_fallthrough
        if (
            gateway is None
            or helper_binding is None
            or original_fallthrough_binding is None
            or group.original_call_opcode is None
            or edge.original.version is not original_fallthrough_binding.version
        ):
            raise SemanticFragmentBackendRejected(
                "call root rollback lacks captured fallthrough authority"
            )

        predecessor = self._resolve_semantic_fragment_version(group.predecessor.version)
        original = self._resolve_semantic_fragment_version(
            original_fallthrough_binding.version
        )
        replacement = self._resolve_semantic_fragment_version(edge.replacement.version)
        tail = predecessor.tail
        if tail is None:
            raise SemanticFragmentBackendRejected(
                "call root rollback lost its captured call tail"
            )
        helper_bound = gateway.identity_index.resolve_logical_version(
            helper_binding.version,
            transaction_id=self._semantic_fragment_transaction_id(),
        )
        helper = (
            None
            if helper_bound is None
            else self.mba.get_mblock(int(helper_bound.serial))
        )
        if helper_bound is not None and helper is None:
            raise SemanticFragmentBackendRejected(
                "call root rollback helper is absent from the MBA"
            )

        known_targets = [original, replacement]
        if helper is not None:
            known_targets.append(helper)
        for target in known_targets:
            target.predset._del(int(predecessor.serial))

        predecessor.type = int(group.original_predecessor_type)
        predecessor.flags = int(group.original_predecessor_flags)
        tail.opcode = int(group.original_call_opcode)
        predecessor.succset.clear()
        predecessor.succset.push_back(int(original.serial))
        if int(predecessor.serial) not in {int(value) for value in original.predset}:
            original.predset.push_back(int(predecessor.serial))
        self._semantic_edge_mark(
            predecessor,
            original,
            replacement,
            *(() if helper is None else (helper,)),
        )

        if helper is not None:
            self._discard_semantic_fragment_blocks((helper,))
            gateway.discard_reserved_insert(helper_binding.version.handle)
            predecessor = self._resolve_semantic_fragment_version(
                group.predecessor.version
            )
            original = self._resolve_semantic_fragment_version(
                original_fallthrough_binding.version
            )

        tail = predecessor.tail
        if (
            int(predecessor.type) != int(group.original_predecessor_type)
            or int(predecessor.flags) != int(group.original_predecessor_flags)
            or tuple(int(value) for value in predecessor.succset)
            != (int(original.serial),)
            or predecessor.nextb is None
            or int(predecessor.nextb.serial) != int(original.serial)
            or tail is None
            or int(tail.opcode) != int(group.original_call_opcode)
        ):
            raise SemanticFragmentBackendRejected(
                "call root rollback did not restore captured authority"
            )
        self._semantic_edge_mark(predecessor, original)

    @staticmethod
    def _semantic_fragment_conditional_group_edges(
        group: SemanticFragmentRootPublicationGroup,
    ) -> tuple[
        SemanticFragmentRootEdgeBinding | None,
        SemanticFragmentRootEdgeBinding | None,
    ]:
        taken = tuple(
            edge
            for edge in group.edges
            if edge.role is SemanticEdgeRole.CONDITIONAL_TAKEN
        )
        fallthrough = tuple(
            edge
            for edge in group.edges
            if edge.role is SemanticEdgeRole.CONDITIONAL_FALLTHROUGH
        )
        if (
            not group.conditional
            or len(taken) > 1
            or len(fallthrough) > 1
            or len(taken) + len(fallthrough) != len(group.edges)
        ):
            raise SemanticFragmentBackendRejected(
                "conditional root group has inconsistent semantic arms"
            )
        return (
            None if not taken else taken[0],
            None if not fallthrough else fallthrough[0],
        )

    def _publish_semantic_fragment_conditional_root_group(
        self,
        group: SemanticFragmentRootPublicationGroup,
    ) -> None:
        """Publish both owned arms while one predecessor snapshot is authoritative."""
        taken_edge, fallthrough_edge = self._semantic_fragment_conditional_group_edges(
            group
        )
        if taken_edge is None or fallthrough_edge is None:
            edge = group.edges[0]
            if edge.role is SemanticEdgeRole.CONDITIONAL_TAKEN:
                self._rewrite_semantic_fragment_taken_root(edge, restore=False)
            else:
                self._publish_semantic_fragment_fallthrough_root(edge)
            return

        predecessor = self._resolve_semantic_fragment_version(group.predecessor.version)
        original_taken_binding = group.original_taken
        original_fallthrough_binding = group.original_fallthrough
        if original_taken_binding is None or original_fallthrough_binding is None:
            raise SemanticFragmentBackendRejected(
                "conditional root group lacks captured original arms"
            )
        original_taken = self._resolve_semantic_fragment_version(
            original_taken_binding.version
        )
        original_fallthrough = self._resolve_semantic_fragment_version(
            original_fallthrough_binding.version
        )
        current_taken, current_fallthrough = self._semantic_edge_conditional_arms(
            predecessor
        )
        if (
            int(current_taken.serial) != int(original_taken.serial)
            or int(current_fallthrough.serial) != int(original_fallthrough.serial)
            or predecessor.nextb is None
            or int(predecessor.nextb.serial) != int(original_fallthrough.serial)
        ):
            raise SemanticFragmentBackendRejected(
                "conditional root group authority changed after preflight"
            )

        # Change the explicit arm before inserting the physical fallthrough
        # helper.  Both writes remain inside this predecessor-scoped operation,
        # and rollback uses the captured two-arm snapshot rather than trying to
        # rediscover a possibly partial live shape.
        self._rewrite_semantic_fragment_taken_root(taken_edge, restore=False)
        self._publish_semantic_fragment_fallthrough_root(fallthrough_edge)

    def _rollback_semantic_fragment_conditional_root_group(
        self,
        group: SemanticFragmentRootPublicationGroup,
    ) -> None:
        """Restore captured predicate authority without trusting live topology."""
        self._semantic_fragment_conditional_group_edges(group)
        gateway = self._mutation_gateway
        original_taken_binding = group.original_taken
        original_fallthrough_binding = group.original_fallthrough
        if (
            gateway is None
            or original_taken_binding is None
            or original_fallthrough_binding is None
            or group.original_conditional_opcode is None
        ):
            raise SemanticFragmentBackendRejected(
                "conditional root rollback lacks captured group authority"
            )

        predecessor = self._resolve_semantic_fragment_version(group.predecessor.version)
        original_taken = self._resolve_semantic_fragment_version(
            original_taken_binding.version
        )
        original_fallthrough = self._resolve_semantic_fragment_version(
            original_fallthrough_binding.version
        )
        tail = predecessor.tail
        if tail is None or getattr(tail, "d", None) is None:
            raise SemanticFragmentBackendRejected(
                "conditional root rollback lost its captured predicate tail"
            )

        helper_binding = next(
            (
                edge.publication_helper
                for edge in group.edges
                if edge.role is SemanticEdgeRole.CONDITIONAL_FALLTHROUGH
            ),
            None,
        )
        helper = None
        if helper_binding is not None:
            helper_bound = gateway.identity_index.resolve_logical_version(
                helper_binding.version,
                transaction_id=self._semantic_fragment_transaction_id(),
            )
            if helper_bound is not None:
                helper = self.mba.get_mblock(int(helper_bound.serial))
                if helper is None:
                    raise SemanticFragmentBackendRejected(
                        "conditional root rollback helper is absent from the MBA"
                    )

        known_targets = [
            original_taken,
            original_fallthrough,
            *(
                self._resolve_semantic_fragment_version(edge.replacement.version)
                for edge in group.edges
            ),
        ]
        if helper is not None:
            known_targets.append(helper)
        for target in known_targets:
            target.predset._del(int(predecessor.serial))

        predecessor.type = int(group.original_predecessor_type)
        predecessor.flags = int(group.original_predecessor_flags)
        tail.opcode = int(group.original_conditional_opcode)
        tail.d.erase()
        tail.d.make_blkref(int(original_taken.serial))
        predecessor.succset.clear()
        predecessor.succset.push_back(int(original_fallthrough.serial))
        predecessor.succset.push_back(int(original_taken.serial))
        original_fallthrough.predset.push_back(int(predecessor.serial))
        original_taken.predset.push_back(int(predecessor.serial))
        self._semantic_edge_mark(
            predecessor,
            original_taken,
            original_fallthrough,
            *known_targets,
        )

        if helper is not None and helper_binding is not None:
            self._discard_semantic_fragment_blocks((helper,))
            gateway.discard_reserved_insert(helper_binding.version.handle)
            predecessor = self._resolve_semantic_fragment_version(
                group.predecessor.version
            )
            original_taken = self._resolve_semantic_fragment_version(
                original_taken_binding.version
            )
            original_fallthrough = self._resolve_semantic_fragment_version(
                original_fallthrough_binding.version
            )

        restored_taken, restored_fallthrough = self._semantic_edge_conditional_arms(
            predecessor
        )
        if (
            int(restored_taken.serial) != int(original_taken.serial)
            or int(restored_fallthrough.serial) != int(original_fallthrough.serial)
            or predecessor.nextb is None
            or int(predecessor.nextb.serial) != int(original_fallthrough.serial)
        ):
            raise SemanticFragmentBackendRejected(
                "conditional root rollback did not restore captured authority"
            )
        self._semantic_edge_mark(
            predecessor,
            original_taken,
            original_fallthrough,
        )

    def _publish_semantic_root_groups(
        self,
        plan: FragmentPlan,
        rollback_token: object,
    ) -> None:
        """Publish every preflighted root edge, retaining exact rollback scope."""
        token = self._semantic_fragment_publication_token(plan, rollback_token)
        gateway = self._mutation_gateway
        if gateway is None:
            raise SemanticFragmentBackendRejected(
                "root publication requires an active mutation gateway"
            )
        for group in token.groups:
            token.attempted_group_ids.append(group.group_id)
            gateway._record_fragment_root_group_publication_attempted(
                plan,
                group.group_id,
            )
            if group.call_fallthrough:
                self._publish_semantic_fragment_call_root_group(group)
            elif group.conditional:
                self._publish_semantic_fragment_conditional_root_group(group)
            else:
                edge = group.edges[0]
                if edge.role is SemanticEdgeRole.DIRECT:
                    if edge.requires_helper:
                        self._publish_semantic_fragment_direct_fallthrough_root(edge)
                    else:
                        self._rewrite_semantic_fragment_direct_root(
                            edge,
                            restore=False,
                        )
                else:
                    raise SemanticFragmentBackendRejected("unsupported root edge role")
            gateway._record_fragment_root_group_publication_succeeded(
                plan,
                group.group_id,
            )

    def _publish_semantic_patch_roots(self, patch_plan, rollback_token) -> None:
        """Authorize every physical root write from its typed PatchStep."""
        from d810.transforms.plan import PatchFragmentRootPublication, PatchPlan

        if (
            not isinstance(patch_plan, PatchPlan)
            or patch_plan.semantic_contract is None
        ):
            raise TypeError("root publication requires a contracted PatchPlan")
        root_steps = tuple(
            step
            for step in patch_plan.steps
            if isinstance(step, PatchFragmentRootPublication)
        )
        plan = patch_plan.semantic_contract.fragment_plan
        token = self._semantic_fragment_publication_token(plan, rollback_token)
        edges = tuple(edge for group in token.groups for edge in group.edges)
        edge_by_key = {
            (edge.root_block_id, edge.predecessor.block_id, edge.role): edge
            for edge in edges
        }
        if len(edge_by_key) != len(edges) or len(root_steps) != len(edges):
            raise SemanticFragmentBackendRejected(
                "semantic PatchPlan root operation inventory differs"
            )
        for step in root_steps:
            if step.predecessor_ref is None:
                raise SemanticFragmentBackendRejected(
                    "semantic PatchPlan root operation lacks predecessor authority"
                )
            key = (
                step.root_ref.local_block_id,
                step.predecessor_ref.local_block_id,
                step.edge_role,
            )
            edge = edge_by_key.pop(key, None)
            helper_id = (
                None
                if edge is None or edge.publication_helper is None
                else edge.publication_helper.block_id
            )
            if (
                edge is None
                or step.original_ref.local_block_id != edge.original.block_id
                or step.fallthrough_helper_id != helper_id
            ):
                raise SemanticFragmentBackendRejected(
                    "semantic PatchPlan root identity authority differs"
                )
        if edge_by_key:
            raise SemanticFragmentBackendRejected(
                "semantic PatchPlan root operation inventory differs"
            )
        self._publish_semantic_root_groups(plan, rollback_token)

    def _rebuild_semantic_fragment_chains(self, plan: FragmentPlan) -> None:
        """Invalidate live chains after publication or rollback."""
        state = self._semantic_fragment_state
        if (
            state is None
            or state.plan_id != plan.plan_id
            or state.atomic_group_id != plan.atomic_group_id
        ):
            raise SemanticFragmentBackendRejected(
                "semantic fragment chain rebuild has no matching staged state"
            )
        self.mba.mark_chains_dirty()

    def _observe_published_semantic_fragment_graph(self, plan: FragmentPlan):
        """Return one post-root live projection plus derived semantics."""
        return observe_published_semantic_fragment_graph(self, plan)

    def _verify_generated_semantic_fragment(self, plan: FragmentPlan) -> None:
        """Run the sole native verifier for a graph-free publication."""
        if not self.semantic_fragment_publication_profile.graph_free:
            raise SemanticFragmentBackendRejected(
                "generated verification requires the graph-free profile"
            )
        state = self._semantic_fragment_state
        if state is None or state.plan_id != plan.plan_id:
            raise SemanticFragmentBackendRejected(
                "generated verification lacks matching staged authority"
            )
        try:
            self.mba.verify(True)
        except RuntimeError:
            for serial in range(int(self.mba.qty)):
                block = self.mba.get_mblock(serial)
                if block is None:
                    continue
                logger.error(
                    "GENERATED verification block: blk%d@0x%X flags=0x%X "
                    "type=%d head=%s tail=%s",
                    int(block.serial),
                    int(block.start),
                    int(block.flags),
                    int(block.type),
                    None
                    if block.head is None
                    else (hex(int(block.head.ea)), int(block.head.opcode)),
                    None
                    if block.tail is None
                    else (hex(int(block.tail.ea)), int(block.tail.opcode)),
                )
            raise

    def _rollback_semantic_fragment_roots(
        self,
        plan: FragmentPlan,
        rollback_token: object,
    ) -> None:
        """Restore every attempted predecessor group in reverse publication order."""
        token = self._semantic_fragment_publication_token(plan, rollback_token)
        gateway = self._mutation_gateway
        if gateway is None:
            raise SemanticFragmentBackendRejected(
                "root rollback requires an active mutation gateway"
            )
        for group_id in reversed(token.attempted_group_ids):
            group = token.group(group_id)
            gateway._record_fragment_root_group_rollback_attempted(
                plan,
                group.group_id,
            )
            try:
                if group.call_fallthrough:
                    self._rollback_semantic_fragment_call_root_group(group)
                elif group.conditional:
                    self._rollback_semantic_fragment_conditional_root_group(group)
                else:
                    edge = group.edges[0]
                    if edge.role is SemanticEdgeRole.DIRECT:
                        if edge.requires_helper:
                            self._rollback_semantic_fragment_direct_fallthrough_root(
                                edge
                            )
                        else:
                            self._rewrite_semantic_fragment_direct_root(
                                edge,
                                restore=True,
                            )
                    else:
                        raise SemanticFragmentBackendRejected(
                            "unsupported root edge role"
                        )
            except Exception:
                gateway._record_fragment_root_group_rollback_finished(
                    plan,
                    group.group_id,
                    succeeded=False,
                )
                raise
            gateway._record_fragment_root_group_rollback_finished(
                plan,
                group.group_id,
                succeeded=True,
            )

    def _complete_semantic_fragment_publication(self, plan: FragmentPlan) -> None:
        """Release transaction-local backend state after committed authority."""
        state = self._semantic_fragment_state
        if (
            state is None
            or state.plan_id != plan.plan_id
            or state.atomic_group_id != plan.atomic_group_id
        ):
            raise SemanticFragmentBackendRejected(
                "semantic fragment completion has no matching staged state"
            )
        if self.semantic_fragment_publication_profile.graph_free:
            from d810.hexrays.mutation.semantic_fragment_origins import (
                publish_semantic_fragment_instruction_origins,
            )

            publish_semantic_fragment_instruction_origins(
                self.mba,
                function_ea=int(self.mba.entry_ea),
                origins={
                    int(live_ea): int(native_ea)
                    for block_origins in state.instruction_origins_by_block_id.values()
                    for live_ea, native_ea in block_origins.items()
                },
            )
        else:
            gateway = self._mutation_gateway
            if gateway is None:
                raise SemanticFragmentBackendRejected(
                    "semantic fragment completion has no mutation gateway"
                )
            helper_ids = {
                helper.helper_block_id for helper in state.fallthrough_helpers
            }
            helper_ids.update(
                helper.helper_block_id
                for helper in state.root_fallthrough_helpers
            )
            release_ids = (
                helper_ids
                | set(plan.owned_originals)
                | set(state.staged_block_ids)
            )
            for block_id in sorted(release_ids):
                binding = state.bindings.get(block_id)
                published = None if binding is None else binding.proxy.resolve()
                bound = (
                    None
                    if published is None
                    else gateway.identity_index.resolve_logical_version(published)
                )
                block = (
                    None
                    if bound is None
                    else self.mba.get_mblock(int(bound.serial))
                )
                if block is None:
                    raise SemanticFragmentBackendRejected(
                        f"committed retained block {block_id!r} is absent"
                    )
                release_committed_block_retention(block)
            if plan.normalization_authority is not None:
                reachable: set[int] = set()
                pending = [0]
                quantity = int(self.mba.qty)
                while pending:
                    serial = pending.pop()
                    if serial in reachable or not 0 <= serial < quantity:
                        continue
                    block = self.mba.get_mblock(serial)
                    if block is None:
                        continue
                    reachable.add(serial)
                    pending.extend(int(value) for value in block.succset)
                for serial in range(1, max(1, quantity - 1)):
                    if serial in reachable:
                        continue
                    block = self.mba.get_mblock(serial)
                    if block is not None:
                        release_committed_block_retention(block)
        self._semantic_fragment_state = None

    def restore_pruned_conditional_now(
        self,
        source: ida_hexrays.mblock_t,
        *,
        taken_target: ida_hexrays.mblock_t,
        fallthrough_target: ida_hexrays.mblock_t,
    ) -> bool:
        """Restore both CFG arms around a surviving conditional tail.

        Hex-Rays can retain the predicate instruction while pruning every CFG
        successor of a detached native tail.  Rebuild the two-way shape with
        an adjacent fallthrough helper, preserving the original condition and
        changing only its block-reference destination.
        """
        gateway = self._mutation_gateway
        if gateway is None:
            raise RuntimeError("conditional restoration requires a mutation gateway")
        source_serial = int(source.serial)
        source_start_ea = int(source.start)
        taken_serial_before_insertion = int(taken_target.serial)
        taken_start_ea = int(taken_target.start)
        fallthrough_serial_before_insertion = int(fallthrough_target.serial)
        fallthrough_start_ea = int(fallthrough_target.start)
        source_handle = gateway.identity_index.handle_for_serial(source_serial)
        taken_handle = gateway.identity_index.handle_for_serial(
            taken_serial_before_insertion
        )
        fallthrough_handle = gateway.identity_index.handle_for_serial(
            fallthrough_serial_before_insertion
        )
        tail = source.tail
        if (
            source.nsucc() != 0
            or tail is None
            or not ida_hexrays.is_mcode_jcond(int(tail.opcode))
            or taken_target is fallthrough_target
            or source_handle is None
            or taken_handle is None
            or fallthrough_handle is None
        ):
            logger.info(
                "pruned conditional restore abstained: "
                "source=blk%d@0x%X nsucc=%d tail=%s taken=blk%d@0x%X "
                "fallthrough=blk%d@0x%X reason=source_shape",
                source_serial,
                source_start_ea,
                int(source.nsucc()),
                None if tail is None else int(tail.opcode),
                taken_serial_before_insertion,
                taken_start_ea,
                fallthrough_serial_before_insertion,
                fallthrough_start_ea,
            )
            return False

        def native_anchor(handle, fallback: int) -> int:
            identity = handle.stable_identity
            if identity is None:
                return int(fallback)
            if identity.exact_instruction_eas:
                return min(int(ea) for ea in identity.exact_instruction_eas)
            return int(identity.native_ranges.intervals[0].start_ea)

        taken_anchor_ea = native_anchor(taken_handle, taken_start_ea)
        fallthrough_anchor_ea = native_anchor(
            fallthrough_handle,
            fallthrough_start_ea,
        )

        self._begin_mutation_batch(
            serial_quantity=int(self.mba.qty),
            kind=StructuralMutationKind.BLOCK_REPLACE,
            description="restore proven pruned conditional fragment",
            planned_operation_count=3,
            plan_items=(
                MbaMutationPlanItem(
                    item_index=0,
                    mutation_kind="insert_fallthrough_helper",
                    source_serial=source_serial,
                    source_anchor_ea=int(tail.ea),
                    source_identity=source_handle.stable_identity,
                    disposition="planned",
                    reason="preserve native predicate and materialize fallthrough",
                ),
                MbaMutationPlanItem(
                    item_index=1,
                    mutation_kind="bind_conditional_taken",
                    source_serial=source_serial,
                    source_anchor_ea=int(tail.ea),
                    source_identity=source_handle.stable_identity,
                    target_serial=taken_serial_before_insertion,
                    target_anchor_ea=taken_anchor_ea,
                    target_identity=taken_handle.stable_identity,
                    disposition="planned",
                    reason="resolver-proven taken route",
                ),
                MbaMutationPlanItem(
                    item_index=2,
                    mutation_kind="bind_conditional_fallthrough",
                    source_serial=source_serial,
                    source_anchor_ea=int(tail.ea),
                    source_identity=source_handle.stable_identity,
                    target_serial=fallthrough_serial_before_insertion,
                    target_anchor_ea=fallthrough_anchor_ea,
                    target_identity=fallthrough_handle.stable_identity,
                    disposition="planned",
                    reason="resolver-proven fallthrough route",
                ),
            ),
        )
        helper_serial = self._build_fallthrough_goto_helper(
            source,
            fallthrough_target,
        )
        if helper_serial is None:
            gateway.abort(reason="fallthrough helper insertion failed")
            logger.info(
                "pruned conditional restore abstained: "
                "source=blk%d@0x%X fallthrough=blk%d@0x%X "
                "reason=fallthrough_helper",
                source_serial,
                source_start_ea,
                fallthrough_serial_before_insertion,
                fallthrough_start_ea,
            )
            return False
        source_binding = gateway.resolve_block(source_handle)
        taken_binding = gateway.resolve_block(taken_handle)
        fallthrough_binding = gateway.resolve_block(fallthrough_handle)
        source = (
            None
            if source_binding is None
            else self.mba.get_mblock(int(source_binding.serial))
        )
        taken_target = (
            None
            if taken_binding is None
            else self.mba.get_mblock(int(taken_binding.serial))
        )
        fallthrough_target = (
            None
            if fallthrough_binding is None
            else self.mba.get_mblock(int(fallthrough_binding.serial))
        )
        helper = self.mba.get_mblock(int(helper_serial))
        if (
            source is None
            or taken_target is None
            or fallthrough_target is None
            or helper is None
            or int(helper.serial) != int(source.serial) + 1
        ):
            gateway.abort(reason="live block handle reacquisition failed")
            logger.info(
                "pruned conditional restore abstained: "
                "source=blk%d@0x%X helper=%s taken=blk%d@0x%X "
                "fallthrough=blk%d@0x%X reason=reacquire",
                source_serial,
                source_start_ea,
                helper_serial,
                taken_serial_before_insertion,
                taken_start_ea,
                fallthrough_serial_before_insertion,
                fallthrough_start_ea,
            )
            return False

        tail = source.tail
        if tail is None or not ida_hexrays.is_mcode_jcond(int(tail.opcode)):
            gateway.abort(reason="native predicate disappeared after helper insertion")
            logger.info(
                "pruned conditional restore abstained: "
                "source=blk%d@0x%X tail=%s reason=tail_after_insertion",
                int(source.serial),
                int(source.start),
                None if tail is None else int(tail.opcode),
            )
            return False
        taken_serial = int(taken_target.serial)
        tail.d = ida_hexrays.mop_t()
        tail.d.make_blkref(taken_serial)
        source.flags &= ~int(ida_hexrays.MBL_GOTO)
        source.type = int(ida_hexrays.BLT_2WAY)
        source.succset.push_back(int(helper.serial))
        source.succset.push_back(taken_serial)
        if int(source.serial) not in {int(pred) for pred in helper.predset}:
            helper.predset.push_back(int(source.serial))
        if int(source.serial) not in {int(pred) for pred in taken_target.predset}:
            taken_target.predset.push_back(int(source.serial))
        self.mark_blocks_dirty_now(
            source,
            helper,
            taken_target,
            fallthrough_target,
        )
        gateway.record_edge_redirect(
            source=source_handle,
            target=taken_handle,
        )
        gateway.record_edge_redirect(
            source=source_handle,
            target=fallthrough_handle,
        )
        gateway.commit()
        return True

    def restore_pruned_direct_now(
        self,
        source: ida_hexrays.mblock_t,
        target: ida_hexrays.mblock_t,
    ) -> bool:
        """Restore one proven edge from a live zero-way detached endpoint."""
        if source.nsucc() != 0:
            return False
        tail = source.tail
        closing_tail = tail is not None and (
            ida_hexrays.is_mcode_jcond(int(tail.opcode))
            or int(tail.opcode)
            in {
                int(ida_hexrays.m_goto),
                int(ida_hexrays.m_ijmp),
                int(ida_hexrays.m_jtbl),
                int(ida_hexrays.m_ret),
            }
        )
        started_batch = (
            self._mutation_gateway is None or not self._mutation_gateway.active
        )
        if started_batch:
            self._begin_mutation_batch(
                serial_quantity=int(self.mba.qty),
                kind=StructuralMutationKind.EDGE_REDIRECT,
                description="restore pruned direct edge",
            )
        insert_goto_instruction(
            source,
            int(target.serial),
            nop_previous_instruction=closing_tail,
        )
        source.type = int(ida_hexrays.BLT_1WAY)
        source.flags |= int(ida_hexrays.MBL_GOTO)
        source.succset.push_back(int(target.serial))
        if int(source.serial) not in {int(pred) for pred in target.predset}:
            target.predset.push_back(int(source.serial))
        self.mark_blocks_dirty_now(source, target)
        gateway = self._mutation_gateway
        if gateway is None:
            raise RuntimeError("direct edge restoration requires a mutation gateway")
        gateway.record_edge_redirect(
            source=gateway.identity_index.handle_for_serial(int(source.serial)),
            target=gateway.identity_index.handle_for_serial(int(target.serial)),
        )
        if started_batch:
            gateway.commit()
        return True

    def collapse_proven_dispatcher_envelope_now(
        self,
        source: ida_hexrays.mblock_t,
        target: ida_hexrays.mblock_t,
    ) -> bool:
        """Replace one normalized resolver envelope with a proven direct edge.

        PREOPT may expose the same native multi-target ``jmp reg`` as either a
        two-way conditional or a one-way jump-table helper.  The caller must
        independently prove that every native arm carries the same dispatcher
        state to ``target``; this method only validates and rewires the local
        one/two-successor envelope.
        """
        old_successor_serials = tuple(int(serial) for serial in source.succset)
        if len(old_successor_serials) not in {1, 2} or source.tail is None:
            return False
        tail_opcode = int(source.tail.opcode)
        if not (
            ida_hexrays.is_mcode_jcond(tail_opcode)
            or tail_opcode
            in {
                int(ida_hexrays.m_goto),
                int(ida_hexrays.m_ijmp),
                int(ida_hexrays.m_jtbl),
                int(ida_hexrays.m_call),
                int(ida_hexrays.m_icall),
            }
        ):
            return False
        old_successors = tuple(
            self.mba.get_mblock(serial) for serial in old_successor_serials
        )
        if any(block is None for block in old_successors):
            return False
        for old_successor in old_successors:
            assert old_successor is not None
            source.succset._del(int(old_successor.serial))
            if int(source.serial) in {
                int(predecessor) for predecessor in old_successor.predset
            }:
                old_successor.predset._del(int(source.serial))
        insert_goto_instruction(
            source,
            int(target.serial),
            nop_previous_instruction=True,
        )
        source.type = int(ida_hexrays.BLT_1WAY)
        source.flags |= int(ida_hexrays.MBL_GOTO)
        if not any(
            int(instruction.opcode)
            in {int(ida_hexrays.m_call), int(ida_hexrays.m_icall)}
            for instruction in self._block_instructions(source)
        ):
            source.flags &= ~int(ida_hexrays.MBL_CALL)
        source.succset.push_back(int(target.serial))
        if int(source.serial) not in {
            int(predecessor) for predecessor in target.predset
        }:
            target.predset.push_back(int(source.serial))
        self.mark_blocks_dirty_now(
            source,
            target,
            *(block for block in old_successors if block is not None),
        )
        return True

    def lower_proven_indirect_transfer_to_goto_now(
        self,
        source: ida_hexrays.mblock_t,
        target: ida_hexrays.mblock_t,
        indirect_instruction_ea: int,
    ) -> bool:
        """Lower one resolver-proven indirect transfer to ``m_goto``.

        At PREOPT Hex-Rays can represent a native ``jmp reg`` as a raw
        ``m_mov`` envelope that later fuses into ``m_call``/``m_icall``.  A
        resolver-cut boundary port proves that this exact native-origin
        instruction is a transfer, not a semantic call.  Replace only that
        instruction and preserve an existing proven edge when present.
        """
        instructions = self._block_instructions(source)
        candidates = tuple(
            instruction
            for instruction in instructions
            if int(instruction.ea) == int(indirect_instruction_ea)
            and int(instruction.opcode)
            in {
                int(ida_hexrays.m_mov),
                int(ida_hexrays.m_call),
                int(ida_hexrays.m_icall),
                int(ida_hexrays.m_ijmp),
            }
        )
        if len(candidates) != 1:
            return False
        indirect_instruction = candidates[0]

        successors = tuple(int(serial) for serial in source.succset)
        synthetic_return = None
        if successors not in ((), (int(target.serial),)):
            if len(successors) != 1:
                return False
            candidate = self.mba.get_mblock(int(successors[0]))
            return_instructions = (
                () if candidate is None else self._block_instructions(candidate)
            )
            if (
                candidate is None
                or int(candidate.nsucc()) != 0
                or len(return_instructions) != 1
                or int(return_instructions[0].opcode) != int(ida_hexrays.m_ret)
            ):
                return False
            synthetic_return = candidate

        instruction_index = instructions.index(indirect_instruction)
        trailing = instructions[instruction_index + 1 :]
        if trailing:
            if (
                len(trailing) != 1
                or int(trailing[0].opcode) != int(ida_hexrays.m_goto)
                or int(trailing[0].l.t) != int(ida_hexrays.mop_b)
                or int(trailing[0].l.b) != int(target.serial)
            ):
                return False

        source.make_nop(indirect_instruction)
        if not trailing:
            insert_goto_instruction(
                source,
                int(target.serial),
                nop_previous_instruction=False,
            )
        if synthetic_return is not None:
            source.succset._del(int(synthetic_return.serial))
            if int(source.serial) in {
                int(predecessor) for predecessor in synthetic_return.predset
            }:
                synthetic_return.predset._del(int(source.serial))
            source.succset.push_back(int(target.serial))
            if int(source.serial) not in {
                int(predecessor) for predecessor in target.predset
            }:
                target.predset.push_back(int(source.serial))
        elif not successors:
            source.succset.push_back(int(target.serial))
            if int(source.serial) not in {
                int(predecessor) for predecessor in target.predset
            }:
                target.predset.push_back(int(source.serial))
        source.type = int(ida_hexrays.BLT_1WAY)
        source.flags |= int(ida_hexrays.MBL_GOTO)
        if not any(
            int(instruction.opcode)
            in {int(ida_hexrays.m_call), int(ida_hexrays.m_icall)}
            for instruction in self._block_instructions(source)
        ):
            source.flags &= ~int(ida_hexrays.MBL_CALL)
        if synthetic_return is None:
            self.mark_blocks_dirty_now(source, target)
        else:
            self.mark_blocks_dirty_now(source, synthetic_return, target)
        return True

    def lower_proven_indirect_transfer_to_conditional_now(
        self,
        source: ida_hexrays.mblock_t,
        taken_target: ida_hexrays.mblock_t,
        fallthrough_target: ida_hexrays.mblock_t,
        *,
        indirect_instruction_ea: int,
        predicate_register: int,
        predicate_size: int,
        predicate_constant: int,
        condition_code: int,
    ) -> bool:
        """Lower one resolver-proven raw indirect cut to an explicit predicate.

        PREOPT can preserve an original ``jmp reg`` as a zero-way raw
        ``m_mov``/``m_icall`` envelope even though its native target bodies are
        absent from the live function MBA.  The static resolver supplies the
        exact x86 comparison semantics and both targets.  Rebuild that proof as
        a direct binary conditional branch so later Hex-Rays maturities see
        ordinary two-way microcode rather than an invented call.  Avoid a
        nested ``setcc`` boolean because Hex-Rays can canonicalize its flag
        semantics with the opposite branch polarity.
        """
        branch_opcode_by_condition_code = {
            2: int(ida_hexrays.m_jb),
            3: int(ida_hexrays.m_jae),
            4: int(ida_hexrays.m_jz),
            5: int(ida_hexrays.m_jnz),
            6: int(ida_hexrays.m_jbe),
            7: int(ida_hexrays.m_ja),
            12: int(ida_hexrays.m_jl),
            13: int(ida_hexrays.m_jge),
            14: int(ida_hexrays.m_jle),
            15: int(ida_hexrays.m_jg),
        }
        condition_code = int(condition_code)
        predicate_size = int(predicate_size)
        branch_opcode = branch_opcode_by_condition_code.get(condition_code)
        current_successors = tuple(int(serial) for serial in source.succset)
        if (
            branch_opcode is None
            or predicate_size <= 0
            or int(predicate_register) < 0
            or source is taken_target
            or source is fallthrough_target
            or taken_target is fallthrough_target
            or len(current_successors) > 1
        ):
            logger.info(
                "resolver conditional cut diagnostic: invalid proof/topology "
                "source=blk%d@0x%x cc=%d size=%d reg=%d successors=%s "
                "taken=blk%d@0x%x fallthrough=blk%d@0x%x",
                int(source.serial),
                int(source.start),
                condition_code,
                predicate_size,
                int(predicate_register),
                current_successors,
                int(taken_target.serial),
                int(taken_target.start),
                int(fallthrough_target.serial),
                int(fallthrough_target.start),
            )
            return False
        synthetic_return = None
        if current_successors:
            synthetic_return = self.mba.get_mblock(current_successors[0])
            return_instructions = (
                ()
                if synthetic_return is None
                else self._block_instructions(synthetic_return)
            )
            if (
                synthetic_return is None
                or int(synthetic_return.nsucc()) != 0
                or len(return_instructions) != 1
                or int(return_instructions[0].opcode) != int(ida_hexrays.m_ret)
            ):
                logger.info(
                    "resolver conditional cut diagnostic: invalid return envelope "
                    "source=blk%d@0x%x successor=%s shape=%s",
                    int(source.serial),
                    int(source.start),
                    current_successors,
                    (
                        None
                        if synthetic_return is None
                        else (
                            int(synthetic_return.serial),
                            int(synthetic_return.type),
                            int(synthetic_return.nsucc()),
                            tuple(int(serial) for serial in synthetic_return.succset),
                            None
                            if synthetic_return.head is None
                            else (
                                int(synthetic_return.head.ea),
                                int(synthetic_return.head.opcode),
                            ),
                            None
                            if synthetic_return.tail is None
                            else (
                                int(synthetic_return.tail.ea),
                                int(synthetic_return.tail.opcode),
                            ),
                        )
                    ),
                )
                return False
        source_instructions = self._block_instructions(source)
        candidates = tuple(
            instruction
            for instruction in source_instructions
            if int(instruction.ea) == int(indirect_instruction_ea)
            and int(instruction.opcode)
            in {
                int(ida_hexrays.m_mov),
                int(ida_hexrays.m_call),
                int(ida_hexrays.m_icall),
                int(ida_hexrays.m_ijmp),
            }
        )
        if len(candidates) != 1 or candidates[0] is not source_instructions[-1]:
            logger.info(
                "resolver conditional cut diagnostic: instruction match failed "
                "source=blk%d@0x%x instruction=0x%x candidates=%s tail=%s",
                int(source.serial),
                int(source.start),
                int(indirect_instruction_ea),
                tuple(
                    (int(instruction.ea), int(instruction.opcode))
                    for instruction in candidates
                ),
                (
                    None
                    if source.tail is None
                    else (int(source.tail.ea), int(source.tail.opcode))
                ),
            )
            return False

        safe_ea = int(indirect_instruction_ea)
        condition = _SyntheticRegisterComparisonCondition(
            branch_opcode=int(branch_opcode),
            predicate_register=int(predicate_register),
            predicate_size=predicate_size,
            predicate_constant=(
                int(predicate_constant) & ((1 << (8 * predicate_size)) - 1)
            ),
        )

        if synthetic_return is None:
            old_dispatcher_serial = int(taken_target.serial)
        else:
            old_dispatcher_serial = int(synthetic_return.serial)
        return self._apply_lower_conditional_state_transition(
            source,
            old_dispatcher_serial=old_dispatcher_serial,
            rewrite_from_ea=safe_ea,
            condition_operand=condition,
            false_target_serial=int(fallthrough_target.serial),
            true_target_serial=int(taken_target.serial),
        )

    def restore_pruned_call_continuation_now(
        self,
        source: ida_hexrays.mblock_t,
        target: ida_hexrays.mblock_t,
    ) -> bool:
        """Restore a proven continuation without appending after a raw call.

        At early maturities an ``m_call`` with no argument-list destination is
        block-closing.  Its continuation must therefore be represented by the
        physically adjacent successor block, never by appending an ``m_goto``
        after the call in the same block.
        """
        tail = source.tail
        if (
            int(source.nsucc()) != 0
            or tail is None
            or int(tail.opcode)
            not in {int(ida_hexrays.m_call), int(ida_hexrays.m_icall)}
        ):
            return False
        helper_serial = self._build_fallthrough_goto_helper(source, target)
        if helper_serial is None:
            return False
        helper = self.mba.get_mblock(int(helper_serial))
        if helper is None or int(helper.serial) != int(source.serial) + 1:
            return False
        source.type = int(ida_hexrays.BLT_1WAY)
        source.succset.push_back(int(helper.serial))
        if int(source.serial) not in {int(pred) for pred in helper.predset}:
            helper.predset.push_back(int(source.serial))
        self.mark_blocks_dirty_now(source, helper, target)
        return True

    def reanchor_block_instructions_now(
        self,
        block: ida_hexrays.mblock_t,
        ea: int,
    ) -> None:
        """Assign one owned provenance EA to every instruction in a block."""
        for instruction in self._block_instructions(block):
            instruction.setaddr(int(ea))
        block.mark_lists_dirty()

    def clear_state_frontier_payload_now(self, block_serial: int) -> None:
        """NOP non-goto instructions in a state-frontier block."""
        blk = self.mba.get_mblock(int(block_serial))
        if blk is None:
            raise RuntimeError(
                f"clear_state_frontier_payload: cannot resolve block={block_serial}"
            )
        cur = blk.head
        while cur is not None:
            nxt = cur.next
            opcode = int(getattr(cur, "opcode", -1))
            if opcode != int(ida_hexrays.m_goto):
                blk.make_nop(cur)
            cur = nxt
        blk.mark_lists_dirty()
        self.mba.mark_chains_dirty()

    def canonicalize_jtbl_case_overlap_now(
        self,
        *,
        jtbl_serial: int,
        retarget_map: dict[int, int] | tuple[tuple[int, int], ...],
        deduplicate: bool = False,
    ) -> int:
        """Retarget and optionally coalesce jump-table cases through DGM."""
        blk = self.mba.get_mblock(int(jtbl_serial))
        if blk is None:
            logger.warning(
                "canonicalize_jtbl_case_overlap: block %d not found", jtbl_serial
            )
            return 0
        normalized_map = (
            dict(retarget_map) if not isinstance(retarget_map, dict) else retarget_map
        )
        changed = 0
        if normalized_map:
            changed += retarget_jtbl_block_cases(blk, normalized_map)
        if deduplicate:
            changed += coalesce_jtbl_cases(blk)
        return int(changed)

    def redirect_fallthrough_edge_now(
        self,
        *,
        source_serial: int,
        old_target_serial: int,
        new_target_serial: int,
    ) -> int:
        """Redirect a 2-way fallthrough arm through an adjacent helper block."""
        src = self.mba.get_mblock(int(source_serial))
        if src is None:
            raise RuntimeError(
                f"redirect_fallthrough_edge: cannot resolve src={source_serial}"
            )
        if src.nsucc() != 2:
            self.queue_goto_change(
                block_serial=int(source_serial),
                new_target=int(new_target_serial),
                description="redirect non-2way fallthrough edge",
            )
            self.apply(defer_post_apply_maintenance=True)
            return int(source_serial)

        conditional_target = (
            int(src.tail.d.b)
            if src.tail is not None
            and ida_hexrays.is_mcode_jcond(src.tail.opcode)
            and src.tail.d is not None
            and src.tail.d.t == ida_hexrays.mop_b
            else None
        )
        if conditional_target == int(old_target_serial):
            self.queue_conditional_target_change(
                block_serial=int(source_serial),
                old_target=int(old_target_serial),
                new_target=int(new_target_serial),
                description="redirect conditional arm",
            )
            self.apply(defer_post_apply_maintenance=True)
            return int(source_serial)

        fallthrough_target = _get_fallthrough_successor_serial(src)
        if fallthrough_target is None:
            raise RuntimeError(
                "redirect_fallthrough_edge: source has no fallthrough "
                f"src={source_serial}"
            )
        if int(fallthrough_target) != int(old_target_serial):
            raise RuntimeError(
                "redirect_fallthrough_edge: fallthrough mismatch "
                f"src={source_serial} expected={old_target_serial} "
                f"actual={fallthrough_target}"
            )

        new_target_blk = self.mba.get_mblock(int(new_target_serial))
        if new_target_blk is None:
            raise RuntimeError(
                f"redirect_fallthrough_edge: cannot resolve new={new_target_serial}"
            )

        old_qty = int(self.mba.qty)
        helper = insert_nop_blk(src)
        if helper is None:
            raise RuntimeError(
                "redirect_fallthrough_edge: failed to synthesize helper "
                f"src={source_serial}"
            )
        self._record_inserted_serial(int(helper.serial), old_qty)
        changed = change_1way_block_successor(
            helper,
            int(new_target_blk.serial),
            verify=False,
        )
        if not changed:
            raise RuntimeError(
                "redirect_fallthrough_edge: failed to retarget helper "
                f"helper={helper.serial} new={new_target_blk.serial}"
            )
        self.mba.mark_chains_dirty()
        return int(helper.serial)

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
        self.modifications.append(
            QueuedModification(
                mod_type=ModificationType.PRIVATE_TERMINAL_SUFFIX,
                block_serial=anchor_serial,
                new_target=shared_entry_serial,
                priority=12,  # After BLOCK_GOTO_CHANGE (10) so anchors already point to shared_entry
                description=description
                or (
                    f"private terminal suffix anchor={anchor_serial} "
                    f"shared_entry={shared_entry_serial} return={return_block_serial} "
                    f"suffix={suffix_serials}"
                ),
                suffix_serials=suffix_serials,
                clone_expected_serials=clone_expected_serials,
            )
        )
        logger.debug(
            "Queued private_terminal_suffix: anchor=%d shared_entry=%d return=%d suffix=%s expected=%s",
            anchor_serial,
            shared_entry_serial,
            return_block_serial,
            suffix_serials,
            clone_expected_serials,
        )
        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_QUEUE_ADDED,
                self._mod_payload(self.modifications[-1]),
            )

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
        self.modifications.append(
            QueuedModification(
                mod_type=ModificationType.PRIVATE_TERMINAL_SUFFIX_GROUP,
                block_serial=anchors[0],  # primary block for logging
                new_target=shared_entry_serial,
                priority=12,
                description=description
                or (
                    f"private terminal suffix group anchors={anchors} "
                    f"shared_entry={shared_entry_serial} return={return_block_serial}"
                ),
                suffix_serials=suffix_serials,
                anchors=anchors,
                per_anchor_clone_expected_serials=per_anchor_clone_expected_serials,
            )
        )
        logger.debug(
            "Queued private_terminal_suffix_group: anchors=%s shared_entry=%d return=%d suffix=%s",
            anchors,
            shared_entry_serial,
            return_block_serial,
            suffix_serials,
        )
        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_QUEUE_ADDED,
                self._mod_payload(self.modifications[-1]),
            )

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
        self.modifications.append(
            QueuedModification(
                mod_type=ModificationType.DIRECT_TERMINAL_LOWERING_GROUP,
                block_serial=sites[0].anchor_serial if sites else 0,
                new_target=shared_entry_serial,
                priority=12,
                suffix_serials=suffix_serials,
                sites=sites,
                description=description
                or (
                    f"direct terminal lowering group "
                    f"shared_entry={shared_entry_serial} return={return_block_serial} "
                    f"sites={len(sites)}"
                ),
            )
        )
        logger.debug(
            "Queued direct_terminal_lowering_group: shared_entry=%d return=%d sites=%d",
            shared_entry_serial,
            return_block_serial,
            len(sites),
        )
        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_QUEUE_ADDED,
                self._mod_payload(self.modifications[-1]),
            )

    def queue_reorder_blocks(
        self,
        *,
        dfs_block_order: tuple[int, ...],
        old_to_new: dict[int, int] | None = None,
        old_to_trampoline: dict[int, int] | None = None,
        description: str = "",
    ) -> None:
        """Queue block reordering in DFS order.

        Must run LAST among all modifications (highest priority number).
        Copies handler blocks to end of MBA in the given order, then remaps
        all serial references across the entire MBA.

        Args:
            dfs_block_order: Ordered block serials to copy.
            old_to_new: Pre-computed old->new serial mapping from PatchPlan.
                When provided, copy_block results are validated against these
                expected serials. When None, serials are determined at runtime.
            old_to_trampoline: Pre-computed old_serial -> trampoline_serial for
                2WAY blocks. When provided, trampoline serials are validated.
            description: Logging description.
        """
        self.modifications.append(
            QueuedModification(
                mod_type=ModificationType.REORDER_BLOCKS,
                block_serial=dfs_block_order[0] if dfs_block_order else 0,
                new_target=None,
                priority=9999,  # Must run LAST
                dfs_block_order=dfs_block_order,
                old_to_new=old_to_new,
                old_to_trampoline=old_to_trampoline,
                description=description
                or (f"reorder {len(dfs_block_order)} blocks in DFS order"),
            )
        )
        logger.debug(
            "Queued reorder_blocks: %d blocks in DFS order",
            len(dfs_block_order),
        )
        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_QUEUE_ADDED,
                self._mod_payload(self.modifications[-1]),
            )

    def has_modifications(self) -> bool:
        """Check if there are any queued modifications."""
        return len(self.modifications) > 0

    def _detect_transactional_batch_conflicts(self) -> str | None:
        """Scan queued modifications for contradictory pairs.

        The transactional pre-gate (apply(transactional=True)) calls this
        before any live mutation. It catches Mode 1 conflicts — two graph
        modifications on the same source block that prescribe different
        targets — which on sub_7FFD3338C040 manifested as:

            mod[26]: RedirectGoto src=76 tgt=11 old=2
            mod[75]: RedirectGoto src=76 tgt=2  old=11

        The pair cancels out: blk[76] ends up at the original dispatcher
        target despite 2 ``emitted`` mods. The Phase 1 rollback wouldn't
        help — both mods succeed individually; the contradiction is at
        the batch level. This gate rejects such batches up front.

        Returns a human-readable description of the first conflict found,
        or ``None`` if the batch is internally consistent.
        """
        graph_mod_types = {
            ModificationType.BLOCK_GOTO_CHANGE,
            ModificationType.BLOCK_TARGET_CHANGE,
            ModificationType.BLOCK_FALLTHROUGH_CHANGE,
            ModificationType.BLOCK_CONVERT_TO_GOTO,
            ModificationType.LOWER_CONDITIONAL_STATE_TRANSITION,
            ModificationType.NORMALIZE_NWAY_DISPATCHER_EXIT,
            ModificationType.BYPASS_DISPATCHER_TRAMPOLINE,
            ModificationType.PHASE_CYCLE_LOWERING,
            ModificationType.EDGE_REDIRECT_VIA_PRED_SPLIT,
        }
        by_source: dict[int, list[tuple[int, QueuedModification]]] = {}
        for idx, mod in enumerate(self.modifications):
            if mod.mod_type not in graph_mod_types:
                continue
            src = getattr(mod, "block_serial", None)
            if src is None:
                continue
            by_source.setdefault(int(src), []).append((idx, mod))
        for src, entries in by_source.items():
            if len(entries) < 2:
                continue
            targets = {
                int(m.new_target)
                for _, m in entries
                if getattr(m, "new_target", None) is not None
            }
            if len(targets) > 1:
                desc = ", ".join(
                    f"mod[{i}]({m.mod_type.name} src={src}"
                    f" tgt={getattr(m, 'new_target', None)})"
                    for i, m in entries
                )
                return (
                    f"contradictory graph mods on blk[{src}]: "
                    f"{len(entries)} mods yielding {len(targets)} distinct "
                    f"new_targets ({sorted(targets)}) — {desc}"
                )
        return None

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

        logger.info(
            "Restoring MBA topology from snapshot (nblocks=%d)", snapshot.num_blocks
        )

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
                    serial,
                    blk.type,
                    snap_blk.block_type,
                    current_succs,
                    target_succs,
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
                    new_flags=None,  # Already set above
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
            self._emit(
                DeferredEvent.DEFERRED_COALESCE_STARTED,
                {
                    **self._base_payload(),
                    "queue_size": len(self.modifications),
                },
            )

        original_count = len(self.modifications)

        # Track seen modifications by (mod_type, block_serial, new_target) for deduplication
        seen_keys: set[tuple] = set()
        # Track blocks that have been modified to detect conflicts
        block_modifications: dict[int, list[QueuedModification]] = {}

        unique_modifications = []

        for mod in self.modifications:
            # Create a key for deduplication
            # For BLOCK_CREATE_WITH_REDIRECT, we key by (type, source_block, target)
            # since multiple redirects to different targets would conflict
            if mod.mod_type == ModificationType.BLOCK_CREATE_WITH_REDIRECT:
                key = (
                    mod.mod_type,
                    mod.block_serial,
                    mod.new_target,
                    mod.target_ref_kind,
                )
            elif (
                mod.mod_type == ModificationType.BLOCK_CREATE_WITH_CONDITIONAL_REDIRECT
            ):
                key = (
                    mod.mod_type,
                    mod.block_serial,
                    mod.new_target,
                    mod.conditional_target,
                    mod.fallthrough_target,
                    mod.old_target,
                    mod.target_ref_kind,
                )
            elif mod.mod_type == ModificationType.BLOCK_DUPLICATE_AND_REDIRECT:
                key = (
                    mod.mod_type,
                    mod.block_serial,
                    mod.via_pred,
                    mod.new_target,
                    mod.conditional_target,
                    mod.fallthrough_target,
                    mod.expected_serial,
                    mod.expected_secondary_serial,
                )
            elif mod.mod_type == ModificationType.BLOCK_DUPLICATE_REPLAY_AND_REDIRECT:
                replay_key = tuple(
                    (row[0], row[1], row[2], row[3])
                    for row in (mod.replay_entries or ())
                )
                key = (mod.mod_type, mod.block_serial, mod.new_target, replay_key)
            elif mod.mod_type in (
                ModificationType.CLONE_CONDITIONAL_AS_GOTO,
                ModificationType.CLONE_CONDITIONAL_AS_GOTO_FROM_BRANCH_ARM,
            ):
                key = (
                    mod.mod_type,
                    mod.block_serial,
                    mod.via_pred,
                    mod.pred_arm,
                    mod.new_target,
                    mod.expected_serial,
                )
            elif mod.mod_type in (
                ModificationType.EDGE_REDIRECT_VIA_PRED_SPLIT,
                ModificationType.EDGE_SPLIT_TRAMPOLINE,
            ):
                key = (
                    mod.mod_type,
                    mod.src_block,
                    mod.old_target,
                    mod.via_pred,
                    mod.new_target,
                )
            elif mod.mod_type == ModificationType.INSN_SCALARIZE_LOCAL_ALIAS_ACCESS:
                key = (
                    mod.mod_type,
                    mod.block_serial,
                    mod.insn_ea,
                    mod.host_opcode,
                    mod.alias_token,
                    mod.base_token,
                    mod.host_text_sha1,
                    mod.value_size,
                )
            elif mod.mod_type == ModificationType.INSN_RETARGET_OUTPUT_STORE:
                key = (
                    mod.mod_type,
                    mod.block_serial,
                    mod.insn_ea,
                    mod.host_opcode,
                    mod.alias_token,
                    mod.base_token,
                    mod.host_text_sha1,
                    mod.value_size,
                )
            elif mod.mod_type == ModificationType.MATERIALIZE_ZERO_WAY_CONDITIONAL:
                key = (
                    mod.mod_type,
                    mod.block_serial,
                    mod.rewrite_from_ea,
                    mod.conditional_target,
                    mod.fallthrough_target,
                )
            elif mod.mod_type == ModificationType.MATERIALIZE_ZERO_WAY_GOTO:
                key = (
                    mod.mod_type,
                    mod.block_serial,
                    mod.rewrite_from_ea,
                    mod.new_target,
                )
            elif mod.mod_type == ModificationType.LOWER_CONDITIONAL_STATE_TRANSITION:
                key = (
                    mod.mod_type,
                    mod.block_serial,
                    mod.old_target,
                    mod.false_target,
                    mod.true_target,
                    mod.rewrite_from_ea,
                    mod.proof_id,
                    mod.state_register,
                    mod.state_size,
                    mod.false_state,
                    mod.true_state,
                    mod.false_state_write_ea,
                    mod.true_state_write_ea,
                )
            elif mod.mod_type == ModificationType.NORMALIZE_NWAY_DISPATCHER_EXIT:
                key = (
                    mod.mod_type,
                    mod.block_serial,
                    mod.dispatcher_entry_serial,
                    mod.keep_target_serial,
                )
            elif mod.mod_type == ModificationType.BYPASS_DISPATCHER_TRAMPOLINE:
                key = (
                    mod.mod_type,
                    mod.block_serial,
                    mod.old_target,
                    mod.new_target,
                )
            elif mod.mod_type == ModificationType.CANONICALIZE_JTBL_CASE_OVERLAP:
                key = (
                    mod.mod_type,
                    mod.block_serial,
                    tuple(mod.retarget_map or ()),
                    mod.deduplicate_cases,
                )
            elif mod.mod_type == ModificationType.PHASE_CYCLE_LOWERING:
                key = (
                    mod.mod_type,
                    mod.phase_header_entries,
                    mod.phase_header_target,
                    mod.phase_body_entries,
                    mod.phase_body_target,
                    mod.phase_next_phase_entries,
                    mod.phase_next_phase_target,
                    mod.phase_terminal_entries,
                    mod.phase_terminal_target,
                )
            else:
                key = (
                    mod.mod_type,
                    mod.block_serial,
                    mod.new_target,
                    mod.target_ref_kind,
                )

            if key in seen_keys:
                logger.debug(
                    "Removing duplicate modification: %s block=%d target=%s",
                    mod.mod_type.name,
                    mod.block_serial,
                    mod.new_target,
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
                        ModificationType.CLONE_CONDITIONAL_AS_GOTO,
                        ModificationType.CLONE_CONDITIONAL_AS_GOTO_FROM_BRANCH_ARM,
                    ):
                        continue  # Handled by edge-specific conflict pass below
                    same_type_mods = [m for m in mods if m.mod_type == mod_type]
                    if len(same_type_mods) > 1:
                        if mod_type == ModificationType.BLOCK_TARGET_CHANGE:
                            grouped_same_type_mods: list[list[QueuedModification]] = []
                            target_groups: dict[
                                int | None, list[QueuedModification]
                            ] = {}
                            for same_type_mod in same_type_mods:
                                target_groups.setdefault(
                                    same_type_mod.old_target, []
                                ).append(same_type_mod)
                            grouped_same_type_mods.extend(target_groups.values())
                        else:
                            grouped_same_type_mods = [same_type_mods]

                        for grouped_mods in grouped_same_type_mods:
                            if len(grouped_mods) <= 1:
                                continue
                            targets = [
                                (m.new_target, m.target_ref_kind) for m in grouped_mods
                            ]
                            if len(set(targets)) <= 1:
                                continue
                            winner = max(grouped_mods, key=lambda m: m.rule_priority)
                            losers = [m for m in grouped_mods if m != winner]

                            logger.warning(
                                "CONFLICT RESOLVED: Block %d - keeping priority=%d (target=%d old_target=%s), "
                                "discarding %s",
                                block_serial,
                                winner.rule_priority,
                                winner.new_target,
                                winner.old_target,
                                [
                                    (
                                        m.rule_priority,
                                        m.new_target,
                                        m.target_ref_kind.name,
                                        m.old_target,
                                    )
                                    for m in losers
                                ],
                            )

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
            ModificationType.MATERIALIZE_ZERO_WAY_GOTO,
            ModificationType.BLOCK_CREATE_WITH_REDIRECT,
            ModificationType.BLOCK_CREATE_WITH_CONDITIONAL_REDIRECT,
            ModificationType.BLOCK_DUPLICATE_AND_REDIRECT,
            ModificationType.BLOCK_DUPLICATE_REPLAY_AND_REDIRECT,
            ModificationType.LOWER_CONDITIONAL_STATE_TRANSITION,
            ModificationType.NORMALIZE_NWAY_DISPATCHER_EXIT,
            ModificationType.BYPASS_DISPATCHER_TRAMPOLINE,
            ModificationType.CANONICALIZE_JTBL_CASE_OVERLAP,
            ModificationType.PHASE_CYCLE_LOWERING,
            ModificationType.EDGE_SPLIT_TRAMPOLINE,
            ModificationType.EDGE_REMOVE,
        }
        terminal_type_rank = {
            ModificationType.BLOCK_GOTO_CHANGE: 1,
            ModificationType.BLOCK_TARGET_CHANGE: 2,
            ModificationType.BLOCK_CONVERT_TO_GOTO: 3,
            ModificationType.MATERIALIZE_ZERO_WAY_GOTO: 4,
            ModificationType.BLOCK_CREATE_WITH_REDIRECT: 5,
            ModificationType.BLOCK_CREATE_WITH_CONDITIONAL_REDIRECT: 6,
            ModificationType.BLOCK_DUPLICATE_AND_REDIRECT: 7,
            ModificationType.BLOCK_DUPLICATE_REPLAY_AND_REDIRECT: 8,
            ModificationType.LOWER_CONDITIONAL_STATE_TRANSITION: 9,
            ModificationType.NORMALIZE_NWAY_DISPATCHER_EXIT: 10,
            ModificationType.BYPASS_DISPATCHER_TRAMPOLINE: 11,
            ModificationType.CANONICALIZE_JTBL_CASE_OVERLAP: 12,
            ModificationType.PHASE_CYCLE_LOWERING: 13,
            ModificationType.EDGE_SPLIT_TRAMPOLINE: 14,
            ModificationType.EDGE_REMOVE: 15,
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
            ModificationType.CLONE_CONDITIONAL_AS_GOTO,
            ModificationType.CLONE_CONDITIONAL_AS_GOTO_FROM_BRANCH_ARM,
        ):
            edge_mods = [m for m in unique_modifications if m.mod_type == edge_type]
            if not edge_mods:
                continue
            edge_groups: dict[tuple, list[QueuedModification]] = {}
            for em in edge_mods:
                if edge_type in (
                    ModificationType.CLONE_CONDITIONAL_AS_GOTO,
                    ModificationType.CLONE_CONDITIONAL_AS_GOTO_FROM_BRANCH_ARM,
                ):
                    group_key = (em.block_serial, em.block_serial, em.via_pred)
                else:
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
                    group_key[0],
                    group_key[1],
                    group_key[2],
                    winner.new_target,
                    winner.rule_priority,
                    [(m.rule_priority, m.new_target) for m in losers],
                )
                for loser in losers:
                    if loser in unique_modifications:
                        unique_modifications.remove(loser)

        remaining_by_block: dict[int, list[QueuedModification]] = {}
        for mod in unique_modifications:
            remaining_by_block.setdefault(mod.block_serial, []).append(mod)

        for block_serial, mods in remaining_by_block.items():
            terminal_mods = [m for m in mods if m.mod_type in terminal_mod_types]
            if len(terminal_mods) <= 1:
                continue

            if all(
                m.mod_type == ModificationType.BLOCK_TARGET_CHANGE
                for m in terminal_mods
            ) and len({m.old_target for m in terminal_mods}) == len(terminal_mods):
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
                [(m.mod_type.name, m.rule_priority, m.new_target) for m in losers],
            )
            for loser in losers:
                if loser in unique_modifications:
                    unique_modifications.remove(loser)

        removed_count = original_count - len(unique_modifications)
        if removed_count > 0:
            logger.info(
                "Coalesced modifications: removed %d duplicates/conflicts (%d -> %d)",
                removed_count,
                original_count,
                len(unique_modifications),
            )

        self.modifications = unique_modifications
        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_COALESCE_FINISHED,
                {
                    **self._base_payload(),
                    "queue_size": len(self.modifications),
                    "removed_count": removed_count,
                },
            )
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
            logger.debug(
                "_repair_wrong_successors: ida_hexrays not available, skipping"
            )
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
                if (
                    blk.type == 3
                ):  # BLT_NWAY: switch dispatch node, skip  --  edges preserved by deferred mods
                    continue
                # IDA verify.cpp: for null-tail blocks, outs = {serial+1} if ns>0, else {}
                # For BLT_1WAY (type 1): ns = 1
                # For BLT_2WAY (type 2): ns = 2
                # For BLT_STOP/0WAY (type 0): ns = 0
                # ns_from_type maps type -> fixed ns
                raw_succset_null = [
                    int(blk.succset[j]) for j in range(blk.succset.size())
                ]
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
                        blk.serial,
                        sorted(current_null),
                        sorted(expected_null),
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
            elif _ihr.m_jcnd <= tail.opcode <= _ihr.m_jle:
                # Conditional branch (m_jcnd..m_jle): fallthrough = serial+1, taken = tail.d.b
                if tail.d is not None and tail.d.t == _ihr.mop_b:
                    next_serial = blk.serial + 1
                    if next_serial < qty:
                        expected = {next_serial, int(tail.d.b)}
                    else:
                        expected = {int(tail.d.b)}
            elif tail.opcode == _ihr.m_jtbl:
                # Switch: all mcases targets
                if (
                    tail.r is not None
                    and tail.r.t == _ihr.mop_c
                    and tail.r.c is not None
                ):
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
                blk.serial,
                blk.type,
                tail.opcode,
                raw_succset,
                sorted(expected),
            )

            # Extra diagnostics for block 210 (INTERR 50860 target) at WARNING
            if blk.serial == 210:
                logger.warning(
                    "blk[210] raw_succset=%s set(raw)=%s expected=%s "
                    "has_duplicates=%s len_raw=%d",
                    raw_succset,
                    sorted(current),
                    sorted(expected),
                    len(raw_succset) != len(current),
                    len(raw_succset),
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
                    blk.serial,
                    tail.opcode if tail is not None else -1,
                    sorted(current),
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
                    int(added_blk.predset[k]) for k in range(added_blk.predset.size())
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

    def take_superseded_count(self) -> int:
        """Consume the count of modifications coalescing removed before apply.

        Conflict resolution legitimately collapses several queued modifications
        that describe the same edge into one, so an applied count alone cannot
        be reconciled against the number of planned PatchPlan steps. A caller
        checking that inventory must add this back:
        ``applied + superseded == planned``.

        Reading is one-shot, and ``apply`` zeroes it at the start of every
        cycle. Both exist so a stale value can never silently *balance* an
        inventory belonging to a later transaction: a reader that arrives
        without a fresh apply sees 0 and the reconciliation fails loudly, which
        is the safe direction for a corruption check.
        """
        count = int(getattr(self, "_superseded_count", 0))
        self._superseded_count = 0
        return count

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
        transactional: bool = False,
        staged_atomic: bool = False,
    ) -> int:
        """Apply queued work and close its receipt on every exit path."""
        # Scope the coalescing tally to this cycle: a count left over from an
        # earlier transaction must never reconcile a later inventory.
        self._superseded_count = 0
        try:
            return self._apply(
                run_optimize_local=run_optimize_local,
                run_deep_cleaning=run_deep_cleaning,
                verify_each_mod=verify_each_mod,
                rollback_on_verify_failure=rollback_on_verify_failure,
                continue_on_verify_failure=continue_on_verify_failure,
                defer_post_apply_maintenance=defer_post_apply_maintenance,
                enable_snapshot_rollback=enable_snapshot_rollback,
                post_apply_hook=post_apply_hook,
                transactional=transactional,
                staged_atomic=staged_atomic,
            )
        except BaseException as exc:
            self._abort_open_mutation_batch(f"apply raised {type(exc).__name__}: {exc}")
            raise

    def _abort_open_mutation_batch(self, reason: str) -> None:
        gateway = self._mutation_gateway
        if gateway is None or not gateway.active:
            return
        if gateway.current_transaction_attempt is not None:
            return
        try:
            gateway.abort(reason=str(reason))
        except Exception:
            logger.debug("failed to abort open mutation batch", exc_info=True)

    def _record_snapshot_rollback(self, reason: str) -> None:
        """Publish rollback as either an abort or a compensating generation."""
        gateway = self._mutation_gateway
        if gateway is None:
            return
        if gateway.active:
            gateway.abort(reason=str(reason))
            return
        gateway.begin_batch(
            StructuralMutationKind.BLOCK_REPLACE,
            serial_quantity=int(self.mba.qty),
            description=f"snapshot rollback: {reason}",
            planned_operation_count=1,
        )
        gateway.record_unknown_sdk_operation(self.mba)
        gateway.commit()

    def _apply(
        self,
        run_optimize_local: bool = True,
        run_deep_cleaning: bool = False,
        verify_each_mod: bool = False,
        rollback_on_verify_failure: bool = False,
        continue_on_verify_failure: bool = False,
        defer_post_apply_maintenance: bool = False,
        enable_snapshot_rollback: bool = False,
        post_apply_hook: Callable[[], None] | None = None,
        transactional: bool = False,
        staged_atomic: bool = False,
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
            transactional: If True, guarantees all-or-nothing semantics: the
                MBA ends up either fully transformed (every queued modification
                landed) or fully restored to pre-apply state (zero visible
                effect). Implies ``enable_snapshot_rollback=True``; additionally
                restores the snapshot if the per-mod loop aborts mid-batch, if
                the post_apply_hook raises, or if post-apply verify fails.
                Mutations still happen incrementally under the hood — this is
                rollback-based atomicity, not pre-computed write-back. Does
                not avoid the intermediate-state-visible-to-IDA-internals
                window between the first mod and a rollback.
            staged_atomic: If True, run the Strategy B four-phase
                stage-into-new-blocks pipeline: destructive-expressible mods
                are lowered to copy-and-swap sequences, additive + instruction
                mods execute through the normal dispatcher, and orphaned
                originals are deleted in a terminal cleanup phase.  Provides
                real atomicity (intermediate state invisible) on top of the
                existing rollback semantics supplied by
                ``enable_snapshot_rollback``. ``transactional=True`` still
                wraps the staged commit in snapshot rollback; the two kwargs
                may be combined safely.

        Returns:
            Number of successful modifications applied. When ``transactional``
            is True, returns either ``len(self.modifications)`` on full success
            or ``0`` on any failure (after rollback).

        Mutation-stage requirement -- INTERR 50346 (proven 2026-06-06):
            CFG-shape changes -- especially ``BLOCK_CREATE_WITH_REDIRECT``
            inserts (``queue_create_and_redirect``) -- mark the mba graph/chains
            cache (``mbl_graph_t`` at ``*(mba+0x310)``, dirty bit0 of ``+0x30``)
            *structurally dirty*. The decompiler only clears that bit by
            re-running optimization. The post-glbopt finalizer (reverse-engineered
            as hexx64 ``mba_finalize_glbopt__verify_graphcache_50346``, gated by
            ``MBA_LVARS0``) raises **INTERR 50346** at ctree time if it is still
            dirty.

            Therefore drive ``apply()`` for shape-changing mods from an
            ``ida_hexrays.optblock_t.func`` during ``MMAT_GLBOPT1`` and return the
            change count, so IDA re-optimizes and rebuilds the cache (this is the
            ``BlockOptimizerManager`` path). Applying the same mods from a
            *post-optimization* ``Hexrays_Hooks.glbopt`` callback leaves the bit
            set -> INTERR 50346; ``mba.mark_chains_dirty()`` + ``mba.build_graph()``
            afterwards do NOT clear it. Proof + reproduction:
            ``samples/restructuring_lab/specs/2026-06-06-insert-unflatten-phase1.md``
            and ``tests/system/runtime/hexrays/test_insert_unflatten_mini.py``.
        """
        self.transaction_complete = False
        if self._applied:
            logger.warning("DeferredGraphModifier.apply() called twice")
            return 0

        if not self.modifications:
            logger.debug("No modifications to apply")
            return 0

        # Transactional mode forces snapshot capture — we need the pre-state
        # available for any rollback path below (mid-loop abort, post_apply_hook
        # failure, or post-apply verify failure).
        if transactional:
            if not enable_snapshot_rollback:
                logger.info("TRANSACTIONAL: forcing enable_snapshot_rollback=True")
                enable_snapshot_rollback = True

            # Pre-apply consistency gate: detect obviously contradictory
            # batches before any live mutation. Catches Mode 1 bugs (two
            # redirects on the same source block pointing at different
            # targets — which on sub_7FFD manifested as mod[26] redirect
            # 76->11 and mod[75] redirect 76->2 cancelling each other).
            # Strategy A / Phase 2 scope: we don't re-simulate the entire
            # patch plan here (avoids a cfg layer import), but we do reject
            # the easy cases that the earlier planner missed.
            conflict = self._detect_transactional_batch_conflicts()
            if conflict is not None:
                logger.warning(
                    "TRANSACTIONAL: pre-apply consistency gate rejected batch: %s",
                    conflict,
                )
                self._applied = True
                self.verify_failed = True
                return 0

        self._begin_patch_plan_realization()
        self._set_apply_phase("backend_apply", "pre_apply_verify")
        self.last_stale_serial_scan = None

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
        except Exception as exc:
            logger.warning(
                "Pre-apply verify failed (%s: %s); attempting "
                "_repair_wrong_successors before deferred apply",
                type(exc).__name__,
                exc,
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
                        repaired,
                        len(self.modifications),
                    )
                except Exception as exc2:
                    logger.error(
                        "Pre-apply verify still failing after %d repair(s) "
                        "(%s: %s); aborting deferred apply to protect MBA integrity",
                        repaired,
                        type(exc2).__name__,
                        exc2,
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
        self._superseded_count = self.coalesce()

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

        # Sort by priority (lower = earlier). Conditional lowerings insert a
        # helper immediately after their source block, shifting every later
        # serial. Apply those rewrites from the highest source serial downward
        # so one helper insertion cannot move a source that is still pending.
        # All other modifications retain their stable insertion order.
        def _apply_order(
            item: tuple[int, QueuedModification],
        ) -> tuple[int, int, int, int]:
            index, modification = item
            is_conditional = (
                modification.mod_type
                == ModificationType.LOWER_CONDITIONAL_STATE_TRANSITION
            )
            return (
                int(modification.priority),
                1 if is_conditional else 0,
                -int(modification.block_serial) if is_conditional else int(index),
                int(index),
            )

        sorted_mods = [
            modification
            for _, modification in sorted(
                enumerate(self.modifications),
                key=_apply_order,
            )
        ]

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

        sorted_mods, pre_rejected_create = self._pre_reject_create_and_redirects(
            sorted_mods
        )
        sorted_mods, pre_rejected_duplicate = self._pre_reject_duplicate_blocks(
            sorted_mods
        )
        sorted_mods, pre_rejected_clone_goto = (
            self._pre_reject_clone_conditional_as_goto(sorted_mods)
        )
        sorted_mods, pre_rejected_trampolines = self._pre_reject_edge_split_trampolines(
            sorted_mods
        )
        pre_rejected = (
            pre_rejected_create
            + pre_rejected_duplicate
            + pre_rejected_clone_goto
            + pre_rejected_trampolines
        )
        total_mod_count = len(sorted_mods) + pre_rejected
        self._begin_mutation_batch(
            planned_operation_count=len(sorted_mods),
            plan_items=self._build_mutation_plan_items(sorted_mods),
        )

        logger.info("Applying %d queued graph modifications", total_mod_count)

        # D810_DEFERRED_DIAG_PHASES=1 → capture diag DB snapshots at
        # phase boundaries inside DeferredGraphModifier.apply so future
        # diagnostic queries can tell which phase mutated which blocks.
        # Reuses the existing snapshots + blocks tables; no schema changes.
        _diag_phases_enabled = os.getenv("D810_DEFERRED_DIAG_PHASES", "").strip() == "1"

        def _capture_phase_snapshot(phase_label: str) -> None:
            if not _diag_phases_enabled:
                return
            try:
                from d810.hexrays.mba_serializer import mba_to_block_snapshots
                from d810.hexrays.observability import (
                    request_capture_mba_snapshot,
                )

                request_capture_mba_snapshot(
                    blocks=mba_to_block_snapshots(self.mba),
                    label=f"deferred_apply_{phase_label}",
                    func_ea=self.mba.entry_ea if self.mba is not None else 0,
                    maturity="MMAT_GLBOPT1",
                    # ``snapshots.phase`` is a fixed pipeline-stage enum; the
                    # finer deferred-apply boundary remains encoded in label.
                    phase="unknown",
                )
            except Exception:
                logger.debug(
                    "Deferred-apply phase snapshot [%s] failed (non-critical)",
                    phase_label,
                    exc_info=True,
                )

        _capture_phase_snapshot("pre_loop")

        # D810_DEFERRED_WATCH_BLOCKS="75,76" → log after every mod how the
        # watched blocks' succs/preds look, so we can correlate which mod
        # actually mutated a block vs which mod just claimed to.
        watch_blocks: list[int] = []
        _watch_raw = os.getenv("D810_DEFERRED_WATCH_BLOCKS", "").strip()
        if _watch_raw:
            for token in _watch_raw.replace(",", " ").split():
                try:
                    watch_blocks.append(int(token, 10))
                except ValueError:
                    continue

        def _capture_watch_state() -> dict[
            int, tuple[str, tuple[int, ...], tuple[int, ...]]
        ]:
            state: dict[int, tuple[str, tuple[int, ...], tuple[int, ...]]] = {}
            for serial in watch_blocks:
                blk_w = self.mba.get_mblock(int(serial))
                if blk_w is None:
                    state[int(serial)] = ("MISSING", (), ())
                    continue
                succs_w = tuple(blk_w.succ(i) for i in range(blk_w.nsucc()))
                preds_w = tuple(blk_w.pred(i) for i in range(blk_w.npred()))
                nsucc_w = blk_w.nsucc()
                shape = f"{nsucc_w}WAY" if nsucc_w in (0, 1, 2) else f"nsucc={nsucc_w}"
                state[int(serial)] = (shape, succs_w, preds_w)
            return state

        watch_prev = _capture_watch_state() if watch_blocks else {}
        # Persist watch-block transitions to the diag DB when watch is active.
        # Session id lets multiple apply() calls in one DB be distinguished
        # without a separate table for sessions.
        _watch_apply_session = f"apply_{int(time.time() * 1000)}_{id(self)}"

        def _persist_watch_transition(
            *,
            mod_index: int | None,
            mod_type: str,
            phase: str,
            serial: int,
            prev: tuple[str, tuple[int, ...], tuple[int, ...]] | None,
            now: tuple[str, tuple[int, ...], tuple[int, ...]] | None,
        ) -> None:
            if not watch_blocks:
                return
            try:
                from d810.core.observability_cfg import observe_watch_block_transition

                prev_type = prev[0] if prev is not None else None
                prev_succs = prev[1] if prev is not None else None
                prev_preds = prev[2] if prev is not None else None
                now_type = now[0] if now is not None else None
                now_succs = now[1] if now is not None else None
                now_preds = now[2] if now is not None else None
                observe_watch_block_transition(
                    func_ea=(self.mba.entry_ea if self.mba is not None else 0),
                    apply_session_id=_watch_apply_session,
                    mod_index=mod_index,
                    mod_type=mod_type,
                    phase=phase,
                    block_serial=int(serial),
                    prev_type_name=prev_type,
                    prev_succs=prev_succs,
                    prev_preds=prev_preds,
                    now_type_name=now_type,
                    now_succs=now_succs,
                    now_preds=now_preds,
                )
            except Exception:
                logger.debug(
                    "Watch-block transition persist failed (non-critical)",
                    exc_info=True,
                )

        if watch_blocks:
            logger.info(
                "DEFERRED WATCH init: %s",
                {
                    b: f"{s[0]} succs={list(s[1])} preds={list(s[2])}"
                    for b, s in watch_prev.items()
                },
            )
            for _init_serial in watch_blocks:
                _persist_watch_transition(
                    mod_index=None,
                    mod_type="INIT",
                    phase="init",
                    serial=_init_serial,
                    prev=None,
                    now=watch_prev.get(int(_init_serial)),
                )

        if self.event_emitter is not None:
            self._emit(
                DeferredEvent.DEFERRED_APPLY_STARTED,
                {
                    **self._base_payload(),
                    "modification_count": total_mod_count,
                },
            )

        # Log all queued modifications before applying
        logger.info("=== QUEUED MODIFICATIONS (sorted by priority) ===")
        for i, mod in enumerate(sorted_mods):
            logger.info(
                "  [%d] %s (priority=%d) target_blk=%d new_target=%s ref=%s",
                i,
                mod.mod_type.name,
                mod.priority,
                mod.block_serial,
                mod.new_target,
                mod.target_ref_kind.name,
            )
            try:
                blk = self.mba.get_mblock(mod.block_serial)
                logger.info("      BEFORE: %s", _format_block_info(blk))
            except Exception as exc:
                logger.warning(
                    "Queued modification [%d] source introspection failed "
                    "(%s: %s); continuing with serial-only logging",
                    i,
                    type(exc).__name__,
                    exc,
                )
                logger.info(
                    "      BEFORE: blk[%s] <introspection-failed>", mod.block_serial
                )

            if mod.new_target is not None:
                try:
                    target_serial = self._resolve_target_serial(mod)
                    if (
                        target_serial is None
                        or target_serial < 0
                        or target_serial >= self.mba.qty
                    ):
                        logger.info(
                            "      TARGET: future/unmaterialized serial=%s (current qty=%d)",
                            target_serial,
                            self.mba.qty,
                        )
                    else:
                        target_blk = self.mba.get_mblock(target_serial)
                        logger.info("      TARGET: %s", _format_block_info(target_blk))
                except Exception as exc:
                    logger.warning(
                        "Queued modification [%d] target introspection failed "
                        "(%s: %s); continuing with serial-only logging",
                        i,
                        type(exc).__name__,
                        exc,
                    )
                    logger.info(
                        "      TARGET: blk[%s] <introspection-failed>", mod.new_target
                    )

        successful = 0
        failed = pre_rejected
        rolled_back = 0
        recent_modifications: list[dict] = []

        # ────────────────────────────────────────────────────────────────
        # Strategy B staged_atomic path.
        #
        # When requested, route the modification list through the four-phase
        # stage-into-new-blocks pipeline (classify -> stage -> commit ->
        # cleanup).  This gives real atomicity: the intermediate state where
        # the copy exists but external predecessors have not yet been
        # redirected is invisible to any observer of the MBA.
        #
        # The staged path delegates to the existing ``_apply_single``
        # dispatcher for ADDITIVE + INSTRUCTION_ONLY mods (they already
        # follow the copy-block-swap pattern or cannot violate atomicity),
        # and lowers DESTRUCTIVE_EXPRESSIBLE mods into copy-and-swap
        # sequences against ``mba.copy_block``.  UNSUPPORTED mods fall
        # through to the sequential path with a warning.
        # ────────────────────────────────────────────────────────────────
        if staged_atomic:
            (
                staged_successful,
                staged_failed,
            ) = self._apply_staged_atomic(
                sorted_mods,
                recent_modifications=recent_modifications,
            )
            successful += staged_successful
            failed += staged_failed
            # Jump to the post-apply tail (skip the sequential for-loop).
            # The ``goto``-like structure is represented by an early return
            # through ``_finish``; the tail handles optimize_local/verify.
            result = self._finalize_apply(
                successful=successful,
                failed=failed,
                rolled_back=rolled_back,
                sorted_mods=sorted_mods,
                recent_modifications=recent_modifications,
                run_optimize_local=run_optimize_local,
                run_deep_cleaning=run_deep_cleaning,
                defer_post_apply_maintenance=defer_post_apply_maintenance,
                enable_snapshot_rollback=enable_snapshot_rollback,
                post_apply_hook=post_apply_hook,
            )
            self.transaction_complete = (
                result > 0
                and staged_failed == 0
                and staged_successful == len(sorted_mods)
            )
            self._finish_mutation_batch(result)
            return result

        for i, mod in enumerate(sorted_mods):
            self._set_apply_phase("backend_apply", "raw_apply")
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
                self._debug_dump_block_neighborhood(
                    mod.block_serial, f"pre-apply[{i}] source"
                )
                if mod.new_target is not None:
                    self._debug_dump_block_neighborhood(
                        mod.new_target, f"pre-apply[{i}] target"
                    )
            source_before_snapshot = snapshot_block_for_capture(blk)
            target_before_snapshot = None
            if mod.new_target is not None and _is_live_block_serial(
                self.mba,
                mod.new_target,
            ):
                target_before_snapshot = snapshot_block_for_capture(
                    self.mba.get_mblock(mod.new_target)
                )

            rollback_plan = None
            if verify_each_mod and rollback_on_verify_failure:
                rollback_plan = self._prepare_rollback(mod)

            if self.event_emitter is not None:
                self._emit(
                    DeferredEvent.DEFERRED_MOD_STARTED, self._mod_payload(mod, i)
                )

            try:
                result = self._apply_single(mod)
                # Re-fetch block after modification
                blk_after = self.mba.get_mblock(mod.block_serial)
                logger.info("    AFTER:  %s", _format_block_info(blk_after))

                # Watch-block delta audit: log when any watched block changed
                # between the previous mod and this one, and persist each
                # transition to the diag DB's watch_block_transitions table.
                if watch_blocks:
                    watch_now = _capture_watch_state()
                    for serial in watch_blocks:
                        prev = watch_prev.get(int(serial))
                        now = watch_now.get(int(serial))
                        if prev != now:
                            logger.warning(
                                "DEFERRED WATCH[%d]: mod[%d] %s mutated blk[%d] "
                                "prev=%s now=%s",
                                serial,
                                i,
                                mod.mod_type.name,
                                serial,
                                prev,
                                now,
                            )
                            _persist_watch_transition(
                                mod_index=i,
                                mod_type=mod.mod_type.name,
                                phase="per_mod",
                                serial=int(serial),
                                prev=prev,
                                now=now,
                            )
                    watch_prev = watch_now
                source_after_snapshot = snapshot_block_for_capture(blk_after)
                target_after_snapshot = None
                if mod.new_target is not None and _is_live_block_serial(
                    self.mba,
                    mod.new_target,
                ):
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
                                    self._emit(
                                        DeferredEvent.DEFERRED_ROLLBACK_STARTED, _rp
                                    )
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
                                    _rfp["result"] = (
                                        "rolled_back" if _rb_succeeded else "failed"
                                    )
                                    self._emit(
                                        DeferredEvent.DEFERRED_ROLLBACK_FINISHED, _rfp
                                    )

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
                            i,
                            mod.description,
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
                self._maybe_scan_stale_block_refs(subphase="raw_apply_exception")
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
            successful,
            total_mod_count,
            failed,
            rolled_back,
        )
        self.transaction_complete = failed == 0 and successful == len(sorted_mods)

        if successful > 0:
            # Publish the structural receipt before diagnostic capture,
            # cleanup, or Hex-Rays re-entry can transfer control away from this
            # Python frame. A later snapshot restore is a distinct compensating
            # mutation and receives its own generation/receipt.
            self._finish_mutation_batch(successful)

        _capture_phase_snapshot("post_loop")

        # Final watch-block audit: if any watched block drifted from its last
        # captured state with no intervening per-mod delta log, a mutation
        # happened OUTSIDE the deferred_modifier.apply loop (another code path
        # touched self.mba between applies). That's the smoking gun for the
        # dual-apply-path hypothesis.
        if watch_blocks:
            watch_final = _capture_watch_state()
            for serial in watch_blocks:
                prev = watch_prev.get(int(serial))
                now = watch_final.get(int(serial))
                if prev != now:
                    logger.warning(
                        "DEFERRED WATCH[%d] FINAL DRIFT: no mod logged a delta "
                        "yet block changed from prev=%s to final=%s "
                        "(mutation outside deferred_modifier.apply loop)",
                        serial,
                        prev,
                        now,
                    )
                _persist_watch_transition(
                    mod_index=None,
                    mod_type="POST_LOOP",
                    phase="post_loop",
                    serial=int(serial),
                    prev=prev,
                    now=now,
                )
            watch_prev = watch_final
            logger.info(
                "DEFERRED WATCH final: %s",
                {
                    b: f"{s[0]} succs={list(s[1])} preds={list(s[2])}"
                    for b, s in watch_final.items()
                },
            )

        # Mark chains dirty and run optimizations
        if successful > 0:
            self.mba.mark_chains_dirty()
            self._maybe_scan_stale_block_refs(subphase="after_raw_apply")

        def _finish(result_count: int) -> int:
            """Shared exit: emit APPLY_FINISHED and mark applied."""
            self._applied = True
            self._finish_mutation_batch(result_count)
            if self.event_emitter is not None:
                _fp = self._base_payload()
                _fp.update(
                    {
                        "applied": result_count,
                        "failed": failed,
                        "rolled_back": rolled_back,
                        "verify_failed": self.verify_failed,
                    }
                )
                self._emit(DeferredEvent.DEFERRED_APPLY_FINISHED, _fp)
            return result_count

        # Transactional mid-batch abort: when the apply loop broke early
        # (first-failure-aborts policy), restore from the pre-snapshot so the
        # caller sees a clean "nothing applied" result rather than a partial
        # mutation. This is the distinguishing behavior from plain
        # enable_snapshot_rollback, which only restores on post-apply verify
        # failure.
        if transactional and successful < total_mod_count:
            if self._pre_snapshot is not None:
                logger.warning(
                    "TRANSACTIONAL: mid-batch abort (%d/%d applied, %d failed) "
                    "— restoring pre-snapshot (nblocks=%d)",
                    successful,
                    total_mod_count,
                    failed,
                    self._pre_snapshot.num_blocks,
                )
                if self._restore_from_snapshot(self._pre_snapshot):
                    self._record_snapshot_rollback("transactional mid-batch abort")
                    self.verify_failed = False
                    logger.warning("TRANSACTIONAL: rollback succeeded — returning 0")
                    return _finish(0)
                logger.error(
                    "TRANSACTIONAL: rollback FAILED — MBA is in inconsistent "
                    "state (partial mutation live); caller must abort"
                )
                self.verify_failed = True
                return _finish(successful)
            logger.error(
                "TRANSACTIONAL: requested but no pre_snapshot captured; "
                "cannot roll back partial apply"
            )
            self.verify_failed = True
            return _finish(successful)

        if self.verify_failed:
            logger.warning(
                "Skipping post-apply cleanup because incremental verify has "
                "already failed; caller must treat MBA as suspect"
            )
            return _finish(successful)

        if successful > 0:
            if post_apply_hook is not None:
                self._set_apply_phase("backend_apply", "post_apply_hook")
                if watch_blocks:
                    logger.info(
                        "DEFERRED WATCH pre-post-apply-hook: %s",
                        {
                            b: f"{s[0]} succs={list(s[1])} preds={list(s[2])}"
                            for b, s in _capture_watch_state().items()
                        },
                    )
                try:
                    post_apply_hook()
                    if watch_blocks:
                        post_hook_state = _capture_watch_state()
                        pre_state = watch_prev
                        for serial in watch_blocks:
                            prev = pre_state.get(int(serial))
                            now = post_hook_state.get(int(serial))
                            if prev != now:
                                logger.warning(
                                    "DEFERRED WATCH[%d]: post_apply_hook mutated "
                                    "blk[%d] prev=%s now=%s",
                                    serial,
                                    serial,
                                    prev,
                                    now,
                                )
                            _persist_watch_transition(
                                mod_index=None,
                                mod_type="POST_APPLY_HOOK",
                                phase="post_post_apply_hook",
                                serial=int(serial),
                                prev=prev,
                                now=now,
                            )
                        watch_prev = post_hook_state
                        logger.info(
                            "DEFERRED WATCH post-post-apply-hook: %s",
                            {
                                b: f"{s[0]} succs={list(s[1])} preds={list(s[2])}"
                                for b, s in post_hook_state.items()
                            },
                        )
                    self._maybe_scan_stale_block_refs(subphase="after_post_apply_hook")
                    _capture_phase_snapshot("post_post_apply_hook")
                except Exception as e:
                    contract_violations = getattr(e, "violations", None)
                    contract_summary = getattr(e, "summary", None)
                    self._set_apply_phase(
                        "post_apply_contract"
                        if contract_violations
                        else "backend_apply",
                        "post_apply_hook",
                    )
                    self.verify_failed = True
                    self._maybe_scan_stale_block_refs(
                        subphase="post_apply_hook_exception"
                    )
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
                                        "block_serial": getattr(
                                            v, "block_serial", None
                                        ),
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
                            self._record_snapshot_rollback("post-apply hook failure")
                            self.verify_failed = False
                            logger.warning(
                                "Successfully restored MBA from snapshot after "
                                "post_apply_hook failure"
                            )
                            return _finish(0)
                        logger.error(
                            "Snapshot rollback failed after post_apply_hook failure"
                        )

                    return _finish(successful)

            if defer_post_apply_maintenance:
                return _finish(successful)

            if run_deep_cleaning:
                self._set_apply_phase("backend_apply", "deep_cleaning")
                mba_deep_cleaning(self.mba, call_mba_combine_block=True)
                _capture_phase_snapshot("post_deep_cleaning")
                _cleanup_phase_label = "post_deep_cleaning"
                _cleanup_mod_type = "DEEP_CLEANING"
            elif run_optimize_local:
                self._set_apply_phase("backend_apply", "optimize_local")
                self.mba.optimize_local(0)
                _capture_phase_snapshot("post_optimize_local")
                _cleanup_phase_label = "post_optimize_local"
                _cleanup_mod_type = "OPTIMIZE_LOCAL"
            else:
                # Caller requested no optimize_local. Still run conservative
                # cleanup so deferred CFG rewrites don't leave transient orphans.
                self._set_apply_phase("backend_apply", "deep_cleaning")
                mba_deep_cleaning(self.mba, call_mba_combine_block=False)
                _capture_phase_snapshot("post_conservative_cleanup")
                _cleanup_phase_label = "post_conservative_cleanup"
                _cleanup_mod_type = "CONSERVATIVE_CLEANUP"

            # Persist per-watched-block transitions across the IDA cleanup
            # step — this is where mba.optimize_local(0) typically reshapes
            # blocks (the sub_7FFD blk[75] 2WAY→1WAY mystery is captured here).
            if watch_blocks:
                cleanup_state = _capture_watch_state()
                for serial in watch_blocks:
                    prev = watch_prev.get(int(serial))
                    now = cleanup_state.get(int(serial))
                    if prev != now:
                        logger.warning(
                            "DEFERRED WATCH[%d] %s mutated blk[%d] prev=%s now=%s",
                            serial,
                            _cleanup_phase_label,
                            serial,
                            prev,
                            now,
                        )
                    _persist_watch_transition(
                        mod_index=None,
                        mod_type=_cleanup_mod_type,
                        phase=_cleanup_phase_label,
                        serial=int(serial),
                        prev=prev,
                        now=now,
                    )
                watch_prev = cleanup_state

            self._maybe_scan_stale_block_refs(
                subphase=self.last_apply_subphase or "post_apply_maintenance"
            )

            try:
                self._set_apply_phase("native_verify", "native_verify")
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
                _capture_phase_snapshot("post_verify")
            except RuntimeError:
                # The modifications are already applied in-place and cannot
                # be rolled back.  Setting verify_failed lets callers know
                # the MBA is in a suspect state so they can stop further
                # processing instead of letting IDA continue with a
                # corrupted MBA (which causes hangs at later maturity levels).
                self.verify_failed = True
                self._maybe_scan_stale_block_refs(subphase="native_verify_failure")
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
                        self._record_snapshot_rollback("post-apply verify failure")
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

    # ================================================================
    # staged_atomic (Strategy B) apply pipeline
    # ================================================================
    #
    # Design note: staged_atomic extends Phase 1 rollback semantics with
    # real atomicity.  The four phases (classify / stage / commit / cleanup)
    # ensure that ``mba.verify()``-visible state only transitions between
    # two consistent CFG configurations, never through the in-flight
    # "copy exists but preds not yet redirected" intermediate.
    #
    # Reference template: :py:meth:`_apply_private_terminal_suffix_group`
    # demonstrates the full validate/snapshot/copy/wire/redirect sequence
    # that staged_atomic generalises for the destructive-expressible bucket.

    def _apply_staged_atomic(
        self,
        sorted_mods: "list[QueuedModification]",
        *,
        recent_modifications: "list[dict]",
    ) -> "tuple[int, int]":
        """Execute the four-phase staged_atomic pipeline.

        Phases:
            1. Classify each mod into one of
               ``StagedAtomicClassification`` buckets.
            2. Stage DESTRUCTIVE_EXPRESSIBLE mods: copy the target block
               via ``mba.copy_block``, apply the intended mutation to the
               copy, record a pending rewire for each external predecessor.
            3. Commit: apply ADDITIVE + INSTRUCTION_ONLY mods through
               ``_apply_single`` (they already follow copy-and-swap or
               never touch topology), then replay pending rewires from the
               staging phase so external predecessors now point at the
               copies.
            4. Cleanup: remove orphaned original blocks (reverse-topo order
               so removals don't invalidate earlier serials).  Orphaned
               blocks are those whose predset became empty after commit.

        Failure handling: a required destructive staging failure aborts the
        whole batch before the swap point.  Any copies already staged are
        discarded, so no sibling route can become visible without the failed
        operation.  If commit fails after the swap point, snapshot rollback
        remains the recovery authority.

        Args:
            sorted_mods: Modifications in priority order (already passed
                through coalesce / pre-reject gates).
            recent_modifications: Shared trace buffer for diagnostics.

        Returns:
            Tuple ``(successful, failed)`` with per-mod success counts.
        """
        successful = 0
        failed = 0
        external_sdk_operation_count = 0
        external_sdk_refresh_required = False

        # --- Phase 1: Classify ---------------------------------------
        classified: list[tuple[int, QueuedModification, StagedAtomicClassification]] = [
            (i, mod, classify_for_staged_atomic(mod.mod_type))
            for i, mod in enumerate(sorted_mods)
        ]
        class_counts: dict[StagedAtomicClassification, int] = {}
        for _, _, cls in classified:
            class_counts[cls] = class_counts.get(cls, 0) + 1
        logger.info(
            "staged_atomic classify: %s",
            {c.name: n for c, n in class_counts.items()},
        )

        # --- Phase 2: Stage destructive-expressible mods -------------
        pending_rewires: list[_StagedPendingRewire] = []
        staged_indices: set[int] = set()
        for i, mod, cls in classified:
            if cls != StagedAtomicClassification.DESTRUCTIVE_EXPRESSIBLE:
                continue
            effective_new_target = self._resolve_target_serial(mod)
            if effective_new_target != mod.new_target:
                mod.new_target = effective_new_target
            rewire = self._stage_destructive_mod_via_copy(mod, index=i)
            if rewire is None:
                # A destructive intent is atomic only through copy-and-swap.
                # Sequential fallback would make this operation visible apart
                # from its siblings and invalidate the batch receipt.
                failed += 1
                staged_indices.add(i)
                logger.warning(
                    "staged_atomic: refusing non-atomic fallback for "
                    "mod[%d] %s (block=%d)",
                    i,
                    mod.mod_type.name,
                    mod.block_serial,
                )
                continue
            pending_rewires.append(rewire)
            staged_indices.add(i)
            logger.debug(
                "staged_atomic stage[%d]: %s blk[%d](ea=0x%x) -> copy blk[%d]"
                "(ea=0x%x) (preds_serials=%s)",
                i,
                mod.mod_type.name,
                rewire.original_serial,
                rewire.original_start_ea,
                rewire.new_serial,
                rewire.new_start_ea,
                tuple(
                    int(p.serial) if p is not None else None
                    for p in rewire.preds_to_redirect
                ),
            )

        if failed:
            discarded = self._discard_uncommitted_staged_copies(
                tuple(rewire.new_blk for rewire in pending_rewires)
            )
            if discarded != len(pending_rewires):
                self.verify_failed = True
                logger.error(
                    "staged_atomic: required staging failure discarded only "
                    "%d/%d staged copies",
                    discarded,
                    len(pending_rewires),
                )
            logger.warning(
                "staged_atomic: required staging failure aborted all %d "
                "planned modifications before commit",
                len(sorted_mods),
            )
            return 0, len(sorted_mods)

        # --- Phase 3: Commit ---------------------------------------------
        # 3a. Run ADDITIVE + INSTRUCTION_ONLY + UNSUPPORTED mods directly
        #     through _apply_single.  They are either already atomic
        #     (ADDITIVE — internal copy-and-swap) or cannot violate
        #     atomicity (INSTRUCTION_ONLY — touches insns only).
        # 3b. Replay staged rewires to redirect external predecessors at
        #     the swap point.  Until this step runs, external preds still
        #     observe the pre-modification graph; after this step
        #     completes they observe the mutated graph.  No partial
        #     intermediate is ever visible.
        # Bug 4 fix — redirect Phase 3a mods whose ``new_target`` refers
        # to a *staged* original block so they wire to the copy instead.
        # Without this, an in-place mod (e.g., a refused entry-block
        # goto-change that falls back to ``_apply_single``) wires its
        # source at the ORIGINAL block — which still carries its
        # pre-modification goto — defeating the copy-and-swap entirely.
        #
        # On sub_7FFD this manifested as blk[1] (entry) pointing at
        # original blk[78] (goto dispatcher) instead of copy blk[232]
        # (goto handler blk[14]), collapsing AFTER to ``while(1);``.
        #
        # We use *pointer identity* on ``original_blk`` because
        # copy_block preserves start EA — EAs are ambiguous between
        # original and copy.  The live ``copy_blk.serial`` is read at
        # the moment we rewrite the mod (it is stable under subsequent
        # copy_block calls which only shift BLT_STOP).
        # Map keyed by the ORIGINAL block's live serial (stable through
        # Phase 2 because copy_block only shifts BLT_STOP — not the
        # lower-numbered originals).  SWIG Python wrappers for the same
        # C++ mblock_t pointer are NOT identity-preserving across
        # ``mba.get_mblock`` calls, so we cannot use ``id(blk)``; the
        # serial IS stable between phase-2 end and phase-4 start (no
        # ``remove_block`` has been called yet).
        original_serial_to_copy: dict[int, "ida_hexrays.mblock_t"] = {}
        for r in pending_rewires:
            try:
                k = int(r.original_blk.serial)
            except Exception:
                continue
            original_serial_to_copy[k] = r.new_blk
        logger.info(
            "staged_atomic: Phase 3a built original->copy map with %d "
            "entries (from %d pending_rewires)",
            len(original_serial_to_copy),
            len(pending_rewires),
        )

        # A copy staged later can introduce a new predecessor of an original
        # whose predecessor snapshot was captured earlier in Phase 2.  Close
        # those intra-batch dependencies before the swap: the target rewire
        # must redirect both pre-existing predecessors and every staged copy
        # that now points at the target original.  Otherwise the late copy
        # keeps the original reachable and enters its unmodified topology even
        # though the batch receipt reports every route as committed.
        late_predecessor_count = 0
        for target_rewire in pending_rewires:
            try:
                target_original_serial = int(target_rewire.original_blk.serial)
            except Exception:
                continue
            known_predecessor_ids = {
                id(predecessor) for predecessor in target_rewire.preds_to_redirect
            }
            late_predecessors = []
            for source_rewire in pending_rewires:
                predecessor = source_rewire.new_blk
                if id(predecessor) in known_predecessor_ids:
                    continue
                try:
                    successor_serials = {
                        int(predecessor.succset[index])
                        for index in range(int(predecessor.succset.size()))
                    }
                except Exception:
                    continue
                if target_original_serial not in successor_serials:
                    continue
                late_predecessors.append(predecessor)
                known_predecessor_ids.add(id(predecessor))
            if late_predecessors:
                target_rewire.preds_to_redirect = (
                    *target_rewire.preds_to_redirect,
                    *late_predecessors,
                )
                late_predecessor_count += len(late_predecessors)
        if late_predecessor_count:
            logger.info(
                "staged_atomic: closed %d intra-batch copy-to-original "
                "dependencies before commit",
                late_predecessor_count,
            )

        def _maybe_redirect_to_copy(mod: "QueuedModification") -> None:
            if mod.new_target is None:
                return
            copy_blk = original_serial_to_copy.get(int(mod.new_target))
            if copy_blk is None:
                return
            try:
                new_serial = int(copy_blk.serial)
            except Exception:
                return
            if new_serial == mod.new_target:
                return
            logger.info(
                "staged_atomic: rewriting mod new_target %d -> %d "
                "(original blk has staged copy at live serial %d)",
                mod.new_target,
                new_serial,
                new_serial,
            )
            mod.new_target = new_serial

        for i, mod, cls in classified:
            if i in staged_indices:
                continue  # Handled by staging + commit rewire.
            effective_new_target = self._resolve_target_serial(mod)
            if effective_new_target != mod.new_target:
                mod.new_target = effective_new_target
            _maybe_redirect_to_copy(mod)
            if cls == StagedAtomicClassification.UNSUPPORTED:
                logger.warning(
                    "staged_atomic: mod[%d] %s has no staged lowering; "
                    "falling back to sequential apply",
                    i,
                    mod.mod_type.name,
                )
            try:
                if self._apply_single(mod):
                    successful += 1
                    if cls == StagedAtomicClassification.DESTRUCTIVE_EXPRESSIBLE:
                        external_sdk_refresh_required = True
                        if (
                            mod.mod_type
                            != ModificationType.MATERIALIZE_ZERO_WAY_CONDITIONAL
                        ):
                            external_sdk_operation_count += 1
                    recent_modifications.append(
                        {
                            "index": i,
                            "description": mod.description,
                            "mod_type": mod.mod_type.name,
                            "block_serial": mod.block_serial,
                            "new_target": mod.new_target,
                            "phase": "staged_atomic/commit_additive",
                        }
                    )
                    if len(recent_modifications) > _MAX_CAPTURE_HISTORY:
                        recent_modifications.pop(0)
                else:
                    failed += 1
                    logger.warning(
                        "staged_atomic: commit phase failed for mod[%d] %s",
                        i,
                        mod.mod_type.name,
                    )
            except Exception as exc:
                failed += 1
                logger.error(
                    "staged_atomic: exception during mod[%d] %s: %s",
                    i,
                    mod.mod_type.name,
                    exc,
                )
                import traceback

                logger.error("staged_atomic traceback: %s", traceback.format_exc())

        # 3c. Replay pending rewires (commit the swap).
        committed_rewires: list[_StagedPendingRewire] = []
        for rewire in pending_rewires:
            if self._commit_staged_rewire(rewire):
                successful += 1
                external_sdk_refresh_required = True
                if rewire.mod_type != ModificationType.MATERIALIZE_ZERO_WAY_CONDITIONAL:
                    external_sdk_operation_count += 1
                committed_rewires.append(rewire)
                recent_modifications.append(
                    {
                        "description": (
                            f"staged_rewire ea=0x{rewire.original_start_ea:x}"
                            f"->ea=0x{rewire.new_start_ea:x}"
                        ),
                        "mod_type": rewire.mod_type.name,
                        "phase": "staged_atomic/commit_rewire",
                    }
                )
                if len(recent_modifications) > _MAX_CAPTURE_HISTORY:
                    recent_modifications.pop(0)
            else:
                failed += 1
                logger.warning(
                    "staged_atomic: commit rewire failed for %s ea=0x%x "
                    "-> copy ea=0x%x (staging serials %d -> %d)",
                    rewire.mod_type.name,
                    rewire.original_start_ea,
                    rewire.new_start_ea,
                    rewire.original_serial,
                    rewire.new_serial,
                )

        # --- Phase 4: Cleanup orphaned original blocks ---------------
        # Originals whose external predecessors have all been redirected
        # are now unreachable.  Remove them in reverse-topological (by
        # serial, descending) order so earlier serials are not invalidated.
        # ``remove_block`` is optional on the live IDA API (sometimes
        # exposed, sometimes not); the cleanup step probes for it and
        # falls back to a soft "mark unreachable" if unavailable.
        if committed_rewires:
            cleaned = self._cleanup_orphaned_originals(committed_rewires)
            logger.info(
                "staged_atomic cleanup: removed %d orphaned original blocks",
                cleaned,
            )

        # --- Phase 5: CFG_51814 provenance audit --------------------
        # Walk the MBA and report any non-empty block in a special
        # slot/type (entry serial==0, type==BLT_STOP, type==BLT_XTRN).
        # These would trigger INTERR 51814 during the subsequent
        # ``safe_verify``; logging them here (with serial, type, EAs,
        # succs/preds) gives actionable diagnostics right at the phase
        # boundary instead of a bare INTERR.  If we found offenders,
        # attempt one defensive repair: retype non-special-serial
        # offenders back to a sensible type derived from their succset.
        offenders = _audit_special_block_instructions(
            self.mba,
            phase="staged_atomic/post_cleanup",
        )
        if offenders:
            self._repair_cfg_51814_offenders(offenders)

        if external_sdk_refresh_required:
            gateway = self._mutation_gateway
            if gateway is None or not gateway.active:
                raise RuntimeError(
                    "staged atomic SDK operations require an active mutation gateway"
                )
            gateway.record_external_sdk_operations(
                self.mba,
                operation_count=external_sdk_operation_count,
            )

        self.mba.mark_chains_dirty()
        return successful, failed

    def _discard_uncommitted_staged_copies(
        self,
        blocks: "tuple[ida_hexrays.mblock_t, ...]",
    ) -> int:
        """Remove staged copies before any predecessor swap becomes visible."""
        remover = getattr(self.mba, "remove_block", None)
        if remover is None:
            return 0
        removed = 0
        for block in sorted(
            blocks,
            key=lambda candidate: int(candidate.serial),
            reverse=True,
        ):
            try:
                current_serial = int(block.serial)
                outgoing = tuple(int(successor) for successor in block.succset)
                for successor_serial in outgoing:
                    block.succset._del(successor_serial)
                    successor = self.mba.get_mblock(successor_serial)
                    if successor is not None:
                        successor.predset._del(current_serial)
                incoming = tuple(int(predecessor) for predecessor in block.predset)
                for predecessor_serial in incoming:
                    block.predset._del(predecessor_serial)
                    predecessor = self.mba.get_mblock(predecessor_serial)
                    if predecessor is not None:
                        predecessor.succset._del(current_serial)
                block.mark_lists_dirty()
                remover(block)
                removed += 1
            except Exception:
                logger.error(
                    "staged_atomic: failed to discard uncommitted copy blk[%d]@0x%x",
                    int(getattr(block, "serial", -1)),
                    int(getattr(block, "start", idaapi.BADADDR)),
                    exc_info=True,
                )
        if removed:
            self.mba.mark_chains_dirty()
        return removed

    def _repair_cfg_51814_offenders(
        self,
        offenders: list[dict[str, object]],
    ) -> None:
        """Best-effort repair of CFG_51814 offenders detected by the audit.

        For *type*-based offenders (BLT_STOP / BLT_XTRN assigned to a
        block that now carries instructions in the middle of the CFG),
        we retype based on ``succset`` size:
          * 0 successors → BLT_0WAY
          * 1 successor  → BLT_1WAY
          * 2 successors → BLT_2WAY
          * N successors → BLT_NWAY

        For *serial*-based offenders (serial == 0 but non-empty), there
        is no in-place repair: the entry-block invariant is positional.
        We log and leave it for downstream rollback.
        """
        mba = self.mba
        if mba is None:
            return
        for off in offenders:
            serial = int(off["serial"])
            reason = str(off["reason"])
            if reason == "entry_serial_0":
                logger.error(
                    "CFG_51814 repair: cannot fix entry block blk[%d] "
                    "in-place (positional invariant); leaving for rollback",
                    serial,
                )
                continue
            blk = mba.get_mblock(serial)
            if blk is None:
                continue
            try:
                nsucc = int(blk.succset.size())
            except Exception:
                nsucc = -1
            if nsucc == 0:
                new_type = ida_hexrays.BLT_0WAY
            elif nsucc == 1:
                new_type = ida_hexrays.BLT_1WAY
            elif nsucc == 2:
                new_type = ida_hexrays.BLT_2WAY
            else:
                new_type = ida_hexrays.BLT_NWAY
            try:
                old_type = int(blk.type)
                blk.type = new_type
                logger.warning(
                    "CFG_51814 repair: retyped blk[%d] from %d → %d "
                    "(succs=%d, reason=%s)",
                    serial,
                    old_type,
                    new_type,
                    nsucc,
                    reason,
                )
            except Exception as exc:
                logger.error(
                    "CFG_51814 repair: failed to retype blk[%d]: %s",
                    serial,
                    exc,
                )

    def _stage_destructive_mod_via_copy(
        self,
        mod: "QueuedModification",
        *,
        index: int,
    ) -> "_StagedPendingRewire | None":
        """Stage a destructive-expressible mod as a copy-and-swap.

        The staging step:
          1. Snapshots the target block's external predecessors (serials only).
          2. Copies the target block via ``mba.copy_block`` to append at
             ``mba.qty - 1`` (before BLT_STOP).
          3. Applies the intended mutation to the *copy* using the same
             helpers as the in-place path.
          4. Returns a ``_StagedPendingRewire`` recording the swap that
             must be applied during the commit phase.  Returning ``None``
             signals that staging could not be performed (precondition
             failure, missing block, etc.) — the caller counts that as a
             ``failed`` mod and continues.

        No external predecessor is redirected here; that happens during
        the commit phase.  Until commit runs, any external observer still
        sees the original block wired into the pre-modification CFG.
        """
        mba = self.mba
        if mba is None:
            return None
        resolved_source_serial = self._resolve_serial(mod.block_serial)
        if resolved_source_serial is None:
            return None
        if int(resolved_source_serial) != int(mod.block_serial):
            logger.info(
                "staged_atomic: remapped source blk[%d] -> blk[%d] for %s",
                mod.block_serial,
                resolved_source_serial,
                mod.mod_type.name,
            )
            mod.block_serial = int(resolved_source_serial)
        target_blk = mba.get_mblock(mod.block_serial)
        if target_blk is None:
            logger.warning(
                "staged_atomic stage: blk[%d] not found for mod %s",
                mod.block_serial,
                mod.mod_type.name,
            )
            return None
        # Entry-block guard: serial zero is positionally invariant.
        # Imported blocks can legitimately retain ``mba.entry_ea`` as their
        # broad live start coordinate, so that EA does not establish entry
        # ownership.  Copying/removing serial zero would shift the prologue
        # into the special slot and trigger INTERR 51814.
        try:
            target_serial = int(target_blk.serial)
            target_start = int(target_blk.start)
            mba_entry_ea = int(getattr(mba, "entry_ea", -1))
        except Exception:
            target_serial = -1
            target_start = -1
            mba_entry_ea = -1
        if target_serial == 0:
            logger.warning(
                "staged_atomic stage: refusing to copy entry block "
                "blk[%d] (ea=0x%x, mba.entry_ea=0x%x) for mod %s (target "
                "serial from mod=%d) — entry is positionally invariant; "
                "caller will fall back to sequential apply",
                target_serial,
                target_start,
                mba_entry_ea,
                mod.mod_type.name,
                mod.block_serial,
            )
            return None

        # Snapshot external predecessors as direct ``mblock_t`` pointers
        # (Bug 4 fix).  Pointers are stable across ``copy_block`` /
        # ``insert_block`` and remain valid until that specific block is
        # ``remove_block``'d.  Preds are external blocks we never remove
        # during staged_atomic, so their pointers stay valid through
        # commit.  EA is retained only for diagnostics — copy_block
        # preserves start EAs, so EA-based lookup cannot distinguish
        # original from copy (see _StagedPendingRewire docstring).
        preds_snapshot: list["ida_hexrays.mblock_t"] = []
        original_start_ea = int(target_blk.start)
        for k in range(target_blk.predset.size()):
            pred_serial = int(target_blk.predset[k])
            pred_blk = mba.get_mblock(pred_serial)
            if pred_blk is None:
                logger.debug(
                    "staged_atomic stage: pred blk[%d] of blk[%d] not found; "
                    "skipping pred snapshot entry",
                    pred_serial,
                    target_blk.serial,
                )
                continue
            preds_snapshot.append(pred_blk)

        # Copy target block.  ``mba.copy_block(blk, new_serial, cpblk_flags=3)``
        # inserts the copy at ``new_serial`` (shifting later blocks);
        # we append before BLT_STOP so only BLT_STOP's serial shifts.
        try:
            src_type = int(target_blk.type)
        except Exception:
            src_type = -1
        # Guard: never stage a copy of a special-slot block — copy_block
        # preserves ``type``, so copying a BLT_STOP/BLT_XTRN source would
        # place a special-typed block into the middle of the CFG and
        # trigger INTERR 51814 as soon as the copy has instructions.
        if src_type in (ida_hexrays.BLT_STOP, ida_hexrays.BLT_XTRN):
            logger.warning(
                "staged_atomic stage: refusing to copy special-typed "
                "source blk[%d] type=%d (would propagate special type into "
                "active CFG and trigger CFG_51814)",
                target_blk.serial,
                src_type,
            )
            return None
        try:
            new_blk = copy_block_keep(mba, target_blk, mba.qty - 1)
        except Exception as exc:
            logger.warning(
                "staged_atomic stage: copy_block failed for blk[%d]: %s",
                target_blk.serial,
                exc,
            )
            return None
        if new_blk is None:
            logger.warning(
                "staged_atomic stage: copy_block returned None for blk[%d]",
                target_blk.serial,
            )
            return None
        # Post-copy provenance: log src/copy type + serial/EA, and repair
        # if IDA somehow handed us a special-typed copy (defense in depth).
        try:
            new_type = int(new_blk.type)
        except Exception:
            new_type = -1
        if new_type in (ida_hexrays.BLT_STOP, ida_hexrays.BLT_XTRN):
            logger.error(
                "staged_atomic stage: copy_block returned special-typed "
                "copy blk[%d] type=%d from source blk[%d] type=%d — "
                "repairing by re-stamping copy.type=src.type",
                new_blk.serial,
                new_type,
                target_blk.serial,
                src_type,
            )
            try:
                new_blk.type = src_type
            except Exception as exc:
                logger.error(
                    "staged_atomic stage: failed to repair copy.type: %s",
                    exc,
                )
                self._discard_uncommitted_staged_copies((new_blk,))
                return None
        logger.debug(
            "staged_atomic stage: copy_block src=blk[%d](type=%d ea=0x%x) "
            "-> copy=blk[%d](type=%d ea=0x%x)",
            target_blk.serial,
            src_type,
            int(target_blk.start),
            new_blk.serial,
            int(new_blk.type),
            int(new_blk.start),
        )

        # copy_block inherits predset/succset from the source; wipe
        # predset on the copy so external preds will only route to the
        # copy after the commit phase redirects them explicitly.
        try:
            inherited_preds = [x for x in new_blk.predset]
        except Exception:
            inherited_preds = []
        for p in inherited_preds:
            try:
                new_blk.predset._del(p)
            except Exception:
                # Some SWIG wrappers expose `clear()` only; fall back below.
                pass
        if new_blk.predset.size() > 0:
            try:
                new_blk.predset.clear()
            except Exception:
                pass

        # Apply the intended mutation to the *copy*.
        mutation_ok = self._apply_destructive_on_copy(
            new_blk,
            mod,
            original_blk=target_blk,
        )
        if not mutation_ok:
            logger.warning(
                "staged_atomic stage: mutation failed on copy blk[%d] for mod[%d] %s",
                new_blk.serial,
                index,
                mod.mod_type.name,
            )
            self._discard_uncommitted_staged_copies((new_blk,))
            return None

        try:
            new_start_ea = int(new_blk.start)
        except Exception:
            logger.warning(
                "staged_atomic stage: copy blk[%d] has no readable start EA",
                new_blk.serial,
            )
            self._discard_uncommitted_staged_copies((new_blk,))
            return None

        return _StagedPendingRewire(
            original_blk=target_blk,
            new_blk=new_blk,
            preds_to_redirect=tuple(preds_snapshot),
            mod_type=mod.mod_type,
            original_serial=int(mod.block_serial),
            new_serial=int(new_blk.serial),
            original_start_ea=original_start_ea,
            new_start_ea=new_start_ea,
        )

    def _apply_destructive_on_copy(
        self,
        copy_blk: "ida_hexrays.mblock_t",
        mod: "QueuedModification",
        *,
        original_blk: "ida_hexrays.mblock_t | None" = None,
    ) -> bool:
        """Apply a destructive-expressible mod to the freshly-copied block.

        Dispatches by ``mod.mod_type``.  The copy already inherited the
        original block's succset (and thus its topology); the helpers
        below re-use the same in-place mutation primitives as the
        sequential path — they operate on ``copy_blk`` instead of the
        live target, so the original block's wiring is untouched.
        """
        if mod.mod_type == ModificationType.BLOCK_GOTO_CHANGE:
            if copy_blk.nsucc() != 1:
                return False
            return change_1way_block_successor(
                copy_blk,
                mod.new_target,
                verify=False,
            )
        if mod.mod_type == ModificationType.BLOCK_TARGET_CHANGE:
            if copy_blk.tail is None or copy_blk.nsucc() != 2:
                return False
            return change_2way_block_conditional_successor(
                copy_blk,
                mod.new_target,
                verify=False,
            )
        if mod.mod_type == ModificationType.BLOCK_TERMINAL_GOTO_CHANGE:
            if copy_blk.nsucc() != 0:
                return False
            return change_0way_block_successor(
                copy_blk,
                mod.new_target,
                verify=False,
            )
        if mod.mod_type == ModificationType.BLOCK_CONVERT_TO_GOTO:
            if copy_blk.nsucc() != 2:
                return False
            return make_2way_block_goto(
                copy_blk,
                mod.new_target,
                verify=False,
            )
        if mod.mod_type == ModificationType.MATERIALIZE_ZERO_WAY_CONDITIONAL:
            return self._apply_materialize_zero_way_conditional(
                copy_blk,
                predicate_ea=mod.rewrite_from_ea,
                taken_target_serial=mod.conditional_target,
                fallthrough_target_serial=mod.fallthrough_target,
            )
        if mod.mod_type == ModificationType.MATERIALIZE_ZERO_WAY_GOTO:
            return self._apply_materialize_zero_way_goto(
                copy_blk,
                predicate_ea=mod.rewrite_from_ea,
                target_serial=mod.new_target,
            )
        if mod.mod_type == ModificationType.LOWER_CONDITIONAL_STATE_TRANSITION:
            copied_old_dispatcher = mod.old_target
            copy_successors = tuple(int(successor) for successor in copy_blk.succset)
            if (
                copied_old_dispatcher is not None
                and int(copied_old_dispatcher) not in copy_successors
                and original_blk is not None
            ):
                original_successors = tuple(
                    int(successor) for successor in original_blk.succset
                )
                matching_indices = tuple(
                    index
                    for index, successor in enumerate(original_successors)
                    if int(successor) == int(copied_old_dispatcher)
                )
                if len(matching_indices) != 1 or len(original_successors) != len(
                    copy_successors
                ):
                    return False
                copied_old_dispatcher = copy_successors[matching_indices[0]]
            return self._apply_lower_conditional_state_transition(
                copy_blk,
                old_dispatcher_serial=copied_old_dispatcher,
                rewrite_from_ea=mod.rewrite_from_ea,
                condition_operand=mod.condition_operand,
                false_target_serial=mod.false_target,
                true_target_serial=mod.true_target,
                state_register=mod.state_register,
                state_size=mod.state_size,
                false_state=mod.false_state,
                true_state=mod.true_state,
                false_state_write_ea=mod.false_state_write_ea,
                true_state_write_ea=mod.true_state_write_ea,
            )
        if mod.mod_type == ModificationType.EDGE_REMOVE:
            return remove_block_edge(
                copy_blk,
                mod.new_target,
                verify=False,
            )
        logger.warning(
            "staged_atomic: no copy-mutator for mod_type=%s",
            mod.mod_type.name,
        )
        return False

    def _commit_staged_rewire(
        self,
        rewire: "_StagedPendingRewire",
    ) -> bool:
        """Redirect every external predecessor recorded in ``rewire``.

        This is the swap point for a single destructive-expressible mod.
        Before this method runs, external preds still target the original
        block (identified by ``rewire.original_start_ea``) and observe the
        pre-modification graph.  After it returns, every external pred
        that previously targeted the original now targets the copy
        (identified by ``rewire.new_start_ea``) and observes the
        post-modification graph.  Either all redirects succeed or the
        rewire is counted as ``failed`` — the copy then becomes an
        orphaned new block that Phase 4 cleanup or snapshot rollback can
        remove.

        Bug 3 fix — EA-based re-resolution
        ----------------------------------
        Every block is re-resolved by its captured start EA at this phase
        boundary.  This is required because Phase 2 staging may have
        inserted other copies (shifting serials) between the moment this
        rewire was recorded and the moment we commit it.  If any of the
        captured blocks (original, copy, or a pred) was removed or its
        EA drifted between phases, the corresponding step is skipped
        with a diagnostic log entry instead of silently rewiring the
        wrong block.
        """
        mba = self.mba
        if mba is None:
            return False
        # Bug 4 fix — use mblock_t pointers captured at stage time
        # directly, not EA lookup.  copy_block preserves source.start, so
        # EA-based lookup cannot distinguish original from copy and
        # always returned the original (silently making commits no-ops).
        original = rewire.original_blk
        copy = rewire.new_blk
        if original is None or copy is None:
            logger.warning(
                "staged_atomic commit: null pointer (stage bug?) — "
                "skipping rewire (orig_serial_at_stage=%d copy_serial_at_stage=%d)",
                rewire.original_serial,
                rewire.new_serial,
            )
            return False

        # Live serials — may differ from staging-time snapshot because
        # each ``copy_block(_, qty-1)`` inserts before BLT_STOP which
        # only shifts BLT_STOP itself.  But ``blk.serial`` is live.
        try:
            original_serial = int(original.serial)
            copy_serial = int(copy.serial)
        except Exception:
            logger.warning(
                "staged_atomic commit: serial read failed on orig/copy; skipping rewire"
            )
            return False

        any_failed = False
        for pred_blk in rewire.preds_to_redirect:
            if pred_blk is None:
                continue
            try:
                pred_serial = int(pred_blk.serial)
            except Exception:
                logger.debug(
                    "staged_atomic commit: pred pointer serial read failed; skipping"
                )
                continue
            # Skip preds that no longer target the original (already rewired
            # by an earlier commit step or mod).
            cur_succs = {
                int(pred_blk.succset[k]) for k in range(pred_blk.succset.size())
            }
            if original_serial not in cur_succs:
                continue
            rewired_ok = False
            # ---- Entry-block special case (Bug 1 fix) -----------------
            # The synthetic function-entry block lives at serial 0 and is
            # used by IDA to hold the function's entry edge.  The 1-way
            # mutation helper (``change_1way_block_successor``) rejects
            # serial 0 unconditionally (``blk.serial == 0`` guard at the
            # top of the helper).  That makes the entry edge unredirectable
            # through the normal wiring primitive and causes the
            # ``staged_atomic commit: failed to redirect pred blk[0] ...``
            # warning observed on live functions.
            #
            # Mirror the direct succset/predset ``_del`` + ``push_back``
            # pattern used by ``_post_apply_condition_chain_cleanup`` (unflattener) for
            # dispatcher-edge severing — it is the battle-tested primitive
            # the codebase already uses when the block-0 guard blocks a
            # high-level helper.  This path keeps both sides of the edge
            # consistent (``pred.succset`` + ``original.predset`` /
            # ``copy.predset``) without routing through any goto-materialising
            # helper, which the synthetic entry block cannot host anyway.
            if pred_serial == 0 and pred_blk.nsucc() == 1:
                try:
                    pred_blk.succset._del(original_serial)
                    pred_blk.succset.push_back(copy_serial)
                    original.predset._del(pred_serial)
                    copy.predset.push_back(pred_serial)
                    try:
                        pred_blk.mark_lists_dirty()
                    except Exception:
                        pass
                    logger.debug(
                        "staged_atomic commit: entry blk[0] rewired "
                        "from blk[%d] to copy blk[%d] via direct succset/predset "
                        "(orig_ea=0x%x copy_ea=0x%x)",
                        original_serial,
                        copy_serial,
                        rewire.original_start_ea,
                        rewire.new_start_ea,
                    )
                    rewired_ok = True
                except Exception as exc:
                    logger.warning(
                        "staged_atomic commit: entry blk[0] direct rewire "
                        "from blk[%d] to copy blk[%d] raised: %s",
                        original_serial,
                        copy_serial,
                        exc,
                    )
                    rewired_ok = False
                if not rewired_ok:
                    logger.warning(
                        "staged_atomic commit: failed to redirect pred blk[%d] "
                        "from blk[%d] to copy blk[%d]",
                        pred_serial,
                        original_serial,
                        copy_serial,
                    )
                    any_failed = True
                continue
            if pred_blk.nsucc() == 1:
                rewired_ok = change_1way_block_successor(
                    pred_blk,
                    copy_serial,
                    verify=False,
                )
            elif pred_blk.nsucc() == 2:
                # Rewire the explicit conditional arm directly.  A physical
                # fallthrough cannot remain on the original after a committed
                # copy-and-swap, so route it through an adjacent helper.
                if (
                    pred_blk.tail is not None
                    and getattr(pred_blk.tail, "d", None) is not None
                    and pred_blk.tail.d.b == original_serial
                ):
                    rewired_ok = change_2way_block_conditional_successor(
                        pred_blk,
                        copy_serial,
                        verify=False,
                        old_target=original_serial,
                    )
                else:
                    rewired_ok = self._apply_fallthrough_change(
                        pred_blk,
                        int(copy.serial),
                        old_target=original_serial,
                    )
            else:
                logger.debug(
                    "staged_atomic commit: pred blk[%d] has nsucc=%d; "
                    "skipping (not 1-way or 2-way)",
                    pred_serial,
                    pred_blk.nsucc(),
                )
                continue
            if not rewired_ok:
                logger.warning(
                    "staged_atomic commit: failed to redirect pred blk[%d] "
                    "from blk[%d] to copy blk[%d]",
                    pred_serial,
                    original_serial,
                    copy_serial,
                )
                any_failed = True
        return not any_failed

    def _cleanup_orphaned_originals(
        self,
        committed_rewires: "list[_StagedPendingRewire]",
    ) -> int:
        """Remove original blocks whose external predecessors have been rewired.

        Bug 3 fix — EA-based re-resolution
        ----------------------------------
        Each call to ``mba.remove_block`` shifts the serials of every
        block positionally after the removed block.  Pre-computing a
        "reverse serial" sort order before Phase 4 does *not* prevent
        stale-serial lookups because:

          * serials recorded at Phase 2 staging time may have shifted
            during Phase 2 (further staging inserts) or Phase 3 (commit
            rewires may call other wiring helpers that insert trampolines),
          * each ``remove_block`` inside *this* loop shifts every later
            serial, invalidating the sort key computed before the loop
            started.

        The correct fix is to re-resolve every original block by its
        captured ``original_start_ea`` immediately before we operate on
        it.  ``mblock_t.start`` is stable across all the mutations
        staged_atomic performs, so EA-based lookup always finds the
        right block (or returns ``None`` if it was removed out of band,
        in which case we log + skip).

        The loop order still matters for determinism: we iterate in
        descending ``original_start_ea`` order so that if two originals
        happen to share an EA (which should not happen but is defensive)
        later entries win.  The serial-shift invariance means we no
        longer have to pre-sort by serial.

        Returns the number of blocks actually removed.
        """
        mba = self.mba
        if mba is None:
            return 0
        removed = 0

        # Sort by captured start EA DESC: deterministic order that is
        # independent of the volatile serials.  Each iteration then
        # re-resolves the block via EA so we never dereference a stale
        # serial.
        # Bug 4 fix — use stored mblock_t pointers directly.  Sort by
        # live serial descending so removals don't invalidate earlier
        # iterations' serial arithmetic (we re-read blk.serial per
        # iteration anyway, but the descending sort minimises the
        # number of shift events per iteration).
        def _live_serial(r: "_StagedPendingRewire") -> int:
            try:
                return int(r.original_blk.serial)
            except Exception:
                return -1

        by_serial_desc = sorted(
            committed_rewires,
            key=_live_serial,
            reverse=True,
        )
        for rewire in by_serial_desc:
            original = rewire.original_blk
            if original is None:
                continue
            try:
                current_serial = int(original.serial)
            except Exception:
                logger.warning(
                    "staged_atomic cleanup: original pointer unusable "
                    "(staging serial=%d start_ea=0x%x); skipping",
                    rewire.original_serial,
                    rewire.original_start_ea,
                )
                continue
            # Only remove if it is now unreachable (no predecessors).
            if original.predset.size() != 0:
                logger.debug(
                    "staged_atomic cleanup: blk[%d] (ea=0x%x) still has %d "
                    "predecessors, leaving in place",
                    current_serial,
                    rewire.original_start_ea,
                    original.predset.size(),
                )
                continue
            # ---- Bug 2 fix ---------------------------------------------
            # IDA's ``mba.remove_block`` errors with INTERR 51919 when the
            # block still has succset / predset entries at removal time.
            # Pre-disconnect both sides of every edge the block
            # participates in before calling ``remove_block`` — this
            # mirrors the battle-tested ``_post_apply_condition_chain_cleanup``
            # pattern (unflattener.py L1537) which already severs edges
            # via ``succset._del`` + ``predset._del`` at GLBOPT1 without
            # hitting INTERR 51919.
            #
            # Clear outgoing edges: for every succ, remove original
            # from succ.predset AND remove succ from original.succset.
            try:
                outgoing = [
                    int(original.succset[k]) for k in range(original.succset.size())
                ]
            except Exception:
                outgoing = []
            for succ_serial in outgoing:
                succ_blk = mba.get_mblock(succ_serial)
                try:
                    original.succset._del(succ_serial)
                except Exception:
                    pass
                if succ_blk is not None:
                    try:
                        succ_blk.predset._del(current_serial)
                    except Exception:
                        pass
            # Clear incoming edges defensively (should be empty if rewire
            # worked, but pre-existing bookkeeping drift may leave stale
            # entries; ``remove_block`` INTERRs either way).
            try:
                incoming = [
                    int(original.predset[k]) for k in range(original.predset.size())
                ]
            except Exception:
                incoming = []
            for pred_serial in incoming:
                pred_blk = mba.get_mblock(pred_serial)
                try:
                    original.predset._del(pred_serial)
                except Exception:
                    pass
                if pred_blk is not None:
                    try:
                        pred_blk.succset._del(current_serial)
                    except Exception:
                        pass
            try:
                original.mark_lists_dirty()
            except Exception:
                pass
            try:
                remover = getattr(mba, "remove_block", None)
                if remover is None:
                    logger.debug(
                        "staged_atomic cleanup: mba.remove_block unavailable; "
                        "leaving blk[%d] (ea=0x%x) as unreachable",
                        current_serial,
                        rewire.original_start_ea,
                    )
                    continue
                logger.warning(
                    "staged_atomic cleanup: remove_block(blk[%d] ea=0x%x "
                    "type=%d mod_type=%s)",
                    current_serial,
                    rewire.original_start_ea,
                    int(getattr(original, "type", -1)),
                    rewire.mod_type.name,
                )
                remover(original)
                removed += 1
            except Exception as exc:
                logger.warning(
                    "staged_atomic cleanup: remove_block(blk[%d], ea=0x%x) failed: %s",
                    current_serial,
                    rewire.original_start_ea,
                    exc,
                )
        return removed

    def _finalize_apply(
        self,
        *,
        successful: int,
        failed: int,
        rolled_back: int,
        sorted_mods: "list[QueuedModification]",
        recent_modifications: "list[dict]",
        run_optimize_local: bool,
        run_deep_cleaning: bool,
        defer_post_apply_maintenance: bool,
        enable_snapshot_rollback: bool,
        post_apply_hook: "Callable[[], None] | None",
    ) -> int:
        """Shared tail for the staged_atomic path.

        Mirrors the tail of :py:meth:`apply` (mark dirty, run optimize_local
        or deep cleaning, post-apply hook, native verify, snapshot rollback
        on failure).  Kept as a separate method so the staged_atomic branch
        can share the exact same post-apply contract as the sequential path
        without duplicating ~180 lines of bookkeeping.
        """
        if successful > 0:
            self.mba.mark_chains_dirty()

        def _finish(result_count: int) -> int:
            self._applied = True
            if self.event_emitter is not None:
                _fp = self._base_payload()
                _fp.update(
                    {
                        "applied": result_count,
                        "failed": failed,
                        "rolled_back": rolled_back,
                        "verify_failed": self.verify_failed,
                        "mode": "staged_atomic",
                    }
                )
                self._emit(DeferredEvent.DEFERRED_APPLY_FINISHED, _fp)
            return result_count

        if self.verify_failed:
            logger.warning(
                "staged_atomic: skipping post-apply cleanup -- "
                "verify already failed during commit phase"
            )
            return _finish(successful)

        if successful == 0:
            return _finish(successful)

        if post_apply_hook is not None:
            try:
                post_apply_hook()
            except Exception as exc:
                self.verify_failed = True
                logger.error(
                    "staged_atomic: post_apply_hook raised: %s",
                    exc,
                    exc_info=True,
                )
                capture_failure_artifact(
                    self.mba,
                    "exception during staged_atomic post-apply hook",
                    exc,
                    logger_func=logger.error,
                    capture_metadata={
                        "phase": "staged_atomic/post_apply_hook_exception",
                        "applied_modifications": successful,
                        "queued_modifications": len(sorted_mods),
                        "recent_modifications": list(recent_modifications),
                    },
                )
                if enable_snapshot_rollback and self._pre_snapshot is not None:
                    if self._restore_from_snapshot(self._pre_snapshot):
                        self.verify_failed = False
                        return _finish(0)
                return _finish(successful)

        if defer_post_apply_maintenance:
            return _finish(successful)

        if run_deep_cleaning:
            mba_deep_cleaning(self.mba, call_mba_combine_block=True)
        elif run_optimize_local:
            self.mba.optimize_local(0)
        else:
            mba_deep_cleaning(self.mba, call_mba_combine_block=False)

        try:
            safe_verify(
                self.mba,
                "after staged_atomic modifications",
                logger_func=logger.error,
                capture_metadata={
                    "phase": "staged_atomic/post_apply_verify",
                    "applied_modifications": successful,
                    "queued_modifications": len(sorted_mods),
                    "recent_modifications": list(recent_modifications),
                },
            )
        except RuntimeError:
            self.verify_failed = True
            logger.warning(
                "staged_atomic: MBA verify failed after %d modifications",
                successful,
            )
            if self.event_emitter is not None:
                _vfp = self._base_payload()
                _vfp["result"] = "verify_failed"
                _vfp["error"] = "staged_atomic post-apply verify failed"
                self._emit(DeferredEvent.DEFERRED_VERIFY_FAILED, _vfp)

            if enable_snapshot_rollback and self._pre_snapshot is not None:
                if self._restore_from_snapshot(self._pre_snapshot):
                    self.verify_failed = False
                    return _finish(0)

            try:
                mba_deep_cleaning(self.mba, call_mba_combine_block=False)
                safe_verify(
                    self.mba,
                    "after staged_atomic (recovery)",
                    logger_func=logger.error,
                    capture_metadata={
                        "phase": "staged_atomic/post_apply_recovery_verify",
                        "applied_modifications": successful,
                        "queued_modifications": len(sorted_mods),
                        "recent_modifications": list(recent_modifications),
                    },
                )
                self.verify_failed = False
            except RuntimeError:
                pass

        return _finish(successful)

    def _prepare_rollback(self, mod: QueuedModification) -> tuple[str, callable] | None:
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
                    via_pred,
                    src_block,
                )
                if not change_1way_block_successor(pred_blk, src_block, verify=False):
                    logger.error(
                        "edge_redirect_via_pred_split rollback failed: "
                        "could not rewire pred=%d -> src=%d",
                        via_pred,
                        src_block,
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
                    via_pred,
                    src_block,
                )
                if not change_1way_block_successor(pred_blk, src_block, verify=False):
                    logger.error(
                        "edge_split_trampoline rollback failed: could not rewire pred=%d -> src=%d",
                        via_pred,
                        src_block,
                    )
                    return False
                self.mba.mark_chains_dirty()
                return True

            return (
                f"rollback edge_split_trampoline pred={via_pred} -> src={src_block}",
                _rollback_edge_split_trampoline,
            )

        return None

    def _resolve_serial(self, serial: int | None) -> int | None:
        """Resolve a planned serial through the current-MBA gateway."""
        if serial is None:
            return None
        realized = self._realized_patch_serial_by_bound_serial.get(int(serial))
        if realized is not None:
            return int(realized)
        if self._mutation_gateway is None:
            return int(serial)
        return self._mutation_gateway.resolve_serial(int(serial))

    def current_serial_for_planned(self, serial: int) -> int:
        """Return the current MBA serial for a planned transaction coordinate."""
        resolved = self._resolve_serial(int(serial))
        if resolved is None:
            raise RuntimeError(f"planned block serial {serial} is no longer bound")
        return int(resolved)

    def _begin_mutation_batch(
        self,
        *,
        serial_quantity: int | None = None,
        kind: StructuralMutationKind = StructuralMutationKind.BLOCK_REPLACE,
        description: str = "deferred graph modifier apply",
        planned_operation_count: int = 1,
        plan_items: Iterable[MbaMutationPlanItem] = (),
    ) -> None:
        """Create the sole serial-binding authority for this apply batch."""
        if self._mutation_gateway is not None and self._mutation_gateway.active:
            return
        gateway = self._mutation_gateway
        if gateway is None:
            raise RuntimeError(
                "structural mutation requires a coordinator-owned gateway"
            )
        gateway.begin_batch(
            kind,
            serial_quantity=(
                int(self.mba.qty) if serial_quantity is None else int(serial_quantity)
            ),
            description=description,
            planned_operation_count=int(planned_operation_count),
            plan_items=tuple(plan_items),
        )

    def _build_mutation_plan_items(
        self,
        modifications: Iterable[QueuedModification],
    ) -> tuple[MbaMutationPlanItem, ...]:
        gateway = self._mutation_gateway
        if gateway is None:
            return ()

        def _identity_and_anchor(serial: int | None):
            if serial is None:
                return None, None
            handle = gateway.identity_index.handle_for_serial(int(serial))
            identity = None if handle is None else handle.stable_identity
            if identity is not None:
                anchor = min(
                    identity.exact_instruction_eas,
                    default=identity.native_ranges.intervals[0].start_ea,
                )
                return identity, int(anchor)
            block = self.mba.get_mblock(int(serial))
            if block is None:
                return None, None
            anchor = int(getattr(block, "start", -1) or -1)
            if anchor < 0 or anchor >= 0xFFFFFFFFFFFFFFFF:
                head = getattr(block, "head", None)
                anchor = int(getattr(head, "ea", -1) or -1)
            return (None, anchor) if 0 <= anchor < 0xFFFFFFFFFFFFFFFF else (None, None)

        items = []
        for item_index, modification in enumerate(modifications):
            source_serial = int(modification.block_serial)
            target_serial = (
                None
                if modification.new_target is None
                else int(modification.new_target)
            )
            source_identity, source_anchor = _identity_and_anchor(source_serial)
            target_identity, target_anchor = _identity_and_anchor(target_serial)
            items.append(
                MbaMutationPlanItem(
                    item_index=item_index,
                    mutation_kind=modification.mod_type.name.lower(),
                    source_serial=(
                        source_serial if source_anchor is not None else None
                    ),
                    source_anchor_ea=source_anchor,
                    source_identity=source_identity,
                    target_serial=(
                        target_serial if target_anchor is not None else None
                    ),
                    target_anchor_ea=target_anchor,
                    target_identity=target_identity,
                    disposition="planned",
                    reason="post-filter deferred plan",
                )
            )
        return tuple(items)

    def _finish_mutation_batch(self, applied: int) -> None:
        gateway = self._mutation_gateway
        if gateway is None or not gateway.active:
            return
        if gateway.current_transaction_attempt is not None:
            return
        if int(applied) > 0:
            gateway.commit()
        else:
            gateway.abort()

    def _begin_patch_plan_realization(self) -> None:
        """Cross the typed write boundary before any apply-time SDK activity."""
        gateway = self._mutation_gateway
        if gateway is None or not gateway.active:
            return
        attempt = gateway.current_transaction_attempt
        if attempt is None or gateway.mutation_started:
            return
        gateway.begin_patch_realization(
            attempt,
            plan_refs=tuple(self._patch_plan_ref_by_bound_serial.values()),
        )

    def _record_serial_insertion(
        self,
        insertion_serial: int,
        old_qty: int,
        *,
        created: MbaBlockHandle | None = None,
        bound_serial: int | None = None,
    ) -> None:
        """Synchronously publish the +1 insertion shift to the gateway."""
        started_batch = (
            self._mutation_gateway is None or not self._mutation_gateway.active
        )
        if started_batch:
            self._begin_mutation_batch(
                serial_quantity=int(old_qty),
                kind=StructuralMutationKind.BLOCK_INSERT,
                description="immediate block insertion",
            )
        gateway = self._mutation_gateway
        if gateway is None:
            raise RuntimeError("serial insertion could not start mutation gateway")
        plan_ref = self._patch_plan_ref_by_bound_serial.get(
            int(insertion_serial if bound_serial is None else bound_serial)
        )
        attempt = gateway.current_transaction_attempt
        if plan_ref is not None:
            if attempt is None:
                raise RuntimeError("planned insertion lacks typed attempt authority")
            gateway.bind_reserved_plan_block(
                attempt,
                plan_ref,
                insertion_serial=int(insertion_serial),
                returned_serial=int(insertion_serial),
            )
            if bound_serial is not None:
                self._realized_patch_serial_by_bound_serial[int(bound_serial)] = int(
                    insertion_serial
                )
            if started_batch:
                gateway.commit()
            return
        if created is None:
            gateway.record_observed_insert(
                insertion_serial=int(insertion_serial),
                returned_serial=int(insertion_serial),
            )
        else:
            gateway.record_insert(
                insertion_serial=int(insertion_serial),
                returned_serial=int(insertion_serial),
                created=created,
            )
        if started_batch:
            gateway.commit()

    def _begin_patch_block_creation(self, *bound_serials: int) -> None:
        """Cross the irreversible boundary for explicitly owned creations."""
        gateway = self._mutation_gateway
        if gateway is None or not gateway.active:
            raise RuntimeError("patch creation requires an active mutation gateway")
        attempt = gateway.current_transaction_attempt
        if attempt is None:
            raise RuntimeError("patch creation lacks typed attempt authority")
        plan_refs = tuple(
            self._patch_plan_ref_by_bound_serial[int(bound_serial)]
            for bound_serial in bound_serials
        )
        gateway.authorize_patch_block_creation(attempt, plan_refs=plan_refs)

    def _bind_patch_block_creation(
        self,
        bound_serial: int,
        returned_serial: int,
    ) -> None:
        """Publish one SDK-created block through its exact PlanBlockRef owner."""
        if self._mutation_gateway is None or not self._mutation_gateway.active:
            self._begin_mutation_batch()
        gateway = self._mutation_gateway
        if gateway is None:
            raise RuntimeError("plan block binding could not start mutation gateway")
        plan_ref = self._patch_plan_ref_by_bound_serial.get(int(bound_serial))
        attempt = gateway.current_transaction_attempt
        if plan_ref is None or attempt is None:
            raise RuntimeError("created patch block lacks typed plan authority")
        gateway.bind_reserved_plan_block(
            attempt,
            plan_ref,
            insertion_serial=int(returned_serial),
            returned_serial=int(returned_serial),
        )
        self._realized_patch_serial_by_bound_serial[int(bound_serial)] = int(
            returned_serial
        )

    # BISECT denylist: (block_serial, new_target) pairs to skip.
    # Set via environment: D810_BISECT_SKIP="173:111,76:158"
    _bisect_skip: set[tuple[int, int]] = field(default_factory=set, init=False)

    def _apply_single(self, mod: QueuedModification) -> bool:
        """Apply a single modification. Returns True on success."""
        # Bisect skip gate.
        if not self._bisect_skip and os.environ.get("D810_BISECT_SKIP"):
            for pair in os.environ["D810_BISECT_SKIP"].split(","):
                parts = pair.strip().split(":")
                if len(parts) == 2:
                    self._bisect_skip.add((int(parts[0]), int(parts[1])))
        if (
            self._bisect_skip
            and (mod.block_serial, mod.new_target) in self._bisect_skip
        ):
            logger.info(
                "BISECT: skipping mod block_serial=%d new_target=%d",
                mod.block_serial,
                mod.new_target,
            )
            return True  # Pretend success to not abort batch.
        # Resolve serials through the current-MBA identity index (for example,
        # when a prior block creation consumed a later planned serial).
        if self._mutation_gateway is not None and self._mutation_gateway.active:
            remapped = False
            for attr in (
                "block_serial",
                "new_target",
                "old_target",
                "via_pred",
                "src_block",
                "expected_serial",
                "expected_secondary_serial",
                "final_target",
                "original_redirect_target",
            ):
                if (
                    mod.mod_type == ModificationType.LOWER_CONDITIONAL_STATE_TRANSITION
                    and attr == "old_target"
                ):
                    # This lowering resolves all three arm/dispatcher targets
                    # together inside _apply_lower_conditional_state_transition.
                    # Pre-remapping old_target here resolves that one edge twice.
                    continue
                val = getattr(mod, attr, None)
                if val is not None:
                    new_val = self._resolve_serial(val)
                    if new_val is None or int(new_val) == int(val):
                        continue
                    try:
                        setattr(mod, attr, new_val)
                        remapped = True
                    except (AttributeError, TypeError):
                        pass
            if remapped:
                logger.info(
                    "current-MBA serial bindings applied to mod %s",
                    mod.mod_type.name
                    if hasattr(mod.mod_type, "name")
                    else mod.mod_type,
                )
        blk = self.mba.get_mblock(mod.block_serial)
        if blk is None:
            logger.warning("Block %d not found", mod.block_serial)
            return False

        if mod.mod_type == ModificationType.BLOCK_GOTO_CHANGE:
            return self._apply_goto_change(blk, mod.new_target)

        elif mod.mod_type == ModificationType.BLOCK_TARGET_CHANGE:
            return self._apply_target_change(
                blk,
                mod.new_target,
                mod.old_target,
                expected_helper_serial=mod.expected_serial,
            )

        elif mod.mod_type == ModificationType.BLOCK_TERMINAL_GOTO_CHANGE:
            return self._apply_terminal_goto_change(blk, mod.new_target)

        elif mod.mod_type == ModificationType.BLOCK_CONVERT_TO_GOTO:
            return self._apply_convert_to_goto(blk, mod.new_target)

        elif mod.mod_type == ModificationType.BLOCK_NWAY_NULL_TAIL_DOWNGRADE:
            return self._apply_nway_null_tail_downgrade(
                blk,
                dispatcher_entry_serial=mod.dispatcher_entry_serial,
            )

        elif mod.mod_type == ModificationType.BLOCK_NWAY_GOTO_TYPE_DOWNGRADE:
            return self._apply_nway_goto_type_downgrade(blk)

        elif mod.mod_type == ModificationType.INSN_REMOVE:
            return self._apply_insn_remove(blk, mod.insn_ea)

        elif mod.mod_type == ModificationType.INSN_NOP:
            return self._apply_insn_nop(blk, mod.insn_ea)

        elif mod.mod_type == ModificationType.INSN_CONST_MOV_AND_NOP_PAIR:
            return self._apply_const_mov_and_nop_pair(
                blk,
                mod.insn_body_index,
                mod.secondary_insn_body_index,
                mod.const_value,
                mod.replacement_dest,
                mod.value_size,
            )

        elif mod.mod_type == ModificationType.INSN_ZERO_STATE_WRITE:
            return self._apply_zero_state_write(blk, mod.insn_ea)

        elif mod.mod_type == ModificationType.INSN_PROMOTE_OPERAND_TO_SCALAR:
            return self._apply_promote_operand_to_scalar(
                blk,
                mod.insn_ea,
                mod.host_opcode,
                mod.operand_side,
            )

        elif mod.mod_type == ModificationType.INSN_SCALARIZE_LOCAL_ALIAS_ACCESS:
            return self._apply_scalarize_local_alias_access(
                blk,
                mod.insn_ea,
                mod.host_opcode,
                mod.alias_token,
                mod.base_token,
                mod.host_text_sha1,
                mod.value_size,
            )

        elif mod.mod_type == ModificationType.INSN_RETARGET_OUTPUT_STORE:
            return self._apply_retarget_output_store(
                blk,
                mod.insn_ea,
                mod.host_opcode,
                mod.alias_token,
                mod.base_token,
                mod.host_text_sha1,
                mod.value_size,
            )

        elif mod.mod_type == ModificationType.MATERIALIZE_ZERO_WAY_CONDITIONAL:
            return self._apply_materialize_zero_way_conditional(
                blk,
                predicate_ea=mod.rewrite_from_ea,
                taken_target_serial=mod.conditional_target,
                fallthrough_target_serial=mod.fallthrough_target,
            )

        elif mod.mod_type == ModificationType.MATERIALIZE_ZERO_WAY_GOTO:
            return self._apply_materialize_zero_way_goto(
                blk,
                predicate_ea=mod.rewrite_from_ea,
                target_serial=mod.new_target,
            )

        elif mod.mod_type == ModificationType.LOWER_CONDITIONAL_STATE_TRANSITION:
            return self._apply_lower_conditional_state_transition(
                blk,
                old_dispatcher_serial=mod.old_target,
                rewrite_from_ea=mod.rewrite_from_ea,
                condition_operand=mod.condition_operand,
                false_target_serial=mod.false_target,
                true_target_serial=mod.true_target,
                state_register=mod.state_register,
                state_size=mod.state_size,
                false_state=mod.false_state,
                true_state=mod.true_state,
                false_state_write_ea=mod.false_state_write_ea,
                true_state_write_ea=mod.true_state_write_ea,
            )

        elif mod.mod_type == ModificationType.NORMALIZE_NWAY_DISPATCHER_EXIT:
            return self._apply_normalize_nway_dispatcher_exit(
                blk,
                dispatcher_entry_serial=mod.dispatcher_entry_serial,
                keep_target_serial=mod.keep_target_serial,
            )

        elif mod.mod_type == ModificationType.BYPASS_DISPATCHER_TRAMPOLINE:
            return self._apply_bypass_dispatcher_trampoline(
                blk,
                trampoline_serial=mod.old_target,
                target_serial=mod.new_target,
            )

        elif mod.mod_type == ModificationType.CANONICALIZE_JTBL_CASE_OVERLAP:
            return self._apply_canonicalize_jtbl_case_overlap(
                blk,
                retarget_map=mod.retarget_map or (),
                deduplicate=mod.deduplicate_cases,
            )

        elif mod.mod_type == ModificationType.PHASE_CYCLE_LOWERING:
            return self._apply_phase_cycle_lowering(
                header_entries=mod.phase_header_entries or (),
                header_target=mod.phase_header_target,
                body_entries=mod.phase_body_entries or (),
                body_target=mod.phase_body_target,
                next_phase_entries=mod.phase_next_phase_entries or (),
                next_phase_target=mod.phase_next_phase_target,
                terminal_entries=mod.phase_terminal_entries or (),
                terminal_target=mod.phase_terminal_target,
            )

        elif mod.mod_type == ModificationType.BLOCK_CREATE_WITH_REDIRECT:
            return self._apply_create_and_redirect(
                blk,
                mod.final_target,
                mod.instructions_to_copy,
                mod.is_0_way,
                expected_serial=mod.expected_serial,
                old_target_serial=mod.old_target,
            )

        elif mod.mod_type == ModificationType.BLOCK_CREATE_WITH_CONDITIONAL_REDIRECT:
            return self._apply_create_conditional_redirect(
                blk,
                mod.new_target,
                mod.conditional_target,
                mod.fallthrough_target,
                mod.instructions_to_copy,
                old_target_serial=mod.old_target,
                expected_conditional_serial=mod.expected_conditional_serial,
                expected_fallthrough_serial=mod.expected_fallthrough_serial,
            )

        elif mod.mod_type == ModificationType.BLOCK_DUPLICATE_AND_REDIRECT:
            return self._apply_duplicate_block_and_redirect(
                source_blk=blk,
                pred_serial=mod.via_pred,
                target_serial=mod.new_target,
                conditional_target=mod.conditional_target,
                fallthrough_target=mod.fallthrough_target,
                expected_serial=mod.expected_serial,
                expected_secondary_serial=mod.expected_secondary_serial,
                original_redirect_target=mod.original_redirect_target,
            )

        elif mod.mod_type == ModificationType.BLOCK_DUPLICATE_REPLAY_AND_REDIRECT:
            return self._apply_duplicate_replay_and_redirect(
                source_blk=blk,
                dispatcher_entry_serial=mod.new_target,
                replay_entries=mod.replay_entries or (),
            )

        elif mod.mod_type == ModificationType.CLONE_CONDITIONAL_AS_GOTO:
            return self._apply_clone_conditional_as_goto(
                source_blk=blk,
                pred_serial=mod.via_pred,
                goto_target_serial=mod.new_target,
                expected_serial=mod.expected_serial,
            )

        elif mod.mod_type == ModificationType.CLONE_CONDITIONAL_AS_GOTO_FROM_BRANCH_ARM:
            return self._apply_clone_conditional_as_goto_from_branch_arm(
                source_blk=blk,
                pred_serial=mod.via_pred,
                goto_target_serial=mod.new_target,
                pred_arm=mod.pred_arm,
                expected_serial=mod.expected_serial,
            )

        elif mod.mod_type == ModificationType.EDGE_REDIRECT_VIA_PRED_SPLIT:
            return self._apply_edge_redirect_via_pred_split(
                blk,
                mod.old_target,
                mod.new_target,
                mod.via_pred,
                mod.clone_until,
                mod.source_new_target,
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
                per_anchor_clone_expected_serials=mod.per_anchor_clone_expected_serials
                or (),
            )

        elif mod.mod_type == ModificationType.DIRECT_TERMINAL_LOWERING_GROUP:
            return self._apply_direct_terminal_lowering_group(self.mba, mod)

        elif mod.mod_type == ModificationType.REORDER_BLOCKS:
            return self._apply_reorder_blocks(
                mod.dfs_block_order or (),
                expected_old_to_new=mod.old_to_new,
                expected_old_to_trampoline=mod.old_to_trampoline,
            )

        else:
            logger.warning("Unknown modification type: %s", mod.mod_type)
            return False

    def _apply_goto_change(self, blk: ida_hexrays.mblock_t, new_target: int) -> bool:
        """Redirect a 1-way block successor (tail may be non-goto)."""
        # BLOCK_GOTO_CHANGE is a 1-way-only primitive. Rewriting a 2-way block
        # as goto discards the other successor, which is exactly the legacy
        # corruption mode this guard exists to prevent.
        if blk.nsucc() != 1:
            logger.warning(
                "Block %d is not 1-way (nsucc=%d)",
                blk.serial,
                blk.nsucc(),
            )
            return False

        return change_1way_block_successor(blk, new_target, verify=False)

    def _apply_terminal_goto_change(
        self,
        blk: ida_hexrays.mblock_t,
        new_target: int,
        *,
        instruction_ea: int | None = None,
    ) -> bool:
        """Convert a 0-way block to an optionally native-anchored goto."""
        if blk.nsucc() != 0:
            logger.warning(
                "Block %d is not terminal (nsucc=%d)",
                blk.serial,
                blk.nsucc(),
            )
            return False
        if instruction_ea is None:
            return change_0way_block_successor(blk, new_target, verify=False)
        return change_0way_block_successor(
            blk,
            new_target,
            verify=False,
            instruction_ea=instruction_ea,
        )

    def _apply_target_change(
        self,
        blk: ida_hexrays.mblock_t,
        new_target: int,
        old_target: int | None = None,
        *,
        expected_helper_serial: int | None = None,
    ) -> bool:
        """Change a conditional jump's target."""
        if blk.tail is None:
            return False

        # Check if it's a conditional jump.
        if not _is_redirectable_conditional_tail(blk.tail):
            logger.warning("Block %d doesn't end with conditional jump", blk.serial)
            return False

        conditional_target = (
            int(blk.tail.d.b)
            if blk.tail is not None
            and blk.tail.d is not None
            and blk.tail.d.t == ida_hexrays.mop_b
            else None
        )
        fallthrough_target = _get_fallthrough_successor_serial(blk)
        if (
            old_target is not None
            and fallthrough_target is not None
            and conditional_target is not None
            and int(old_target) == int(fallthrough_target)
            and int(fallthrough_target) != int(conditional_target)
        ):
            return self._apply_fallthrough_change(
                blk,
                new_target,
                old_target=int(old_target),
                expected_helper_serial=expected_helper_serial,
            )

        if expected_helper_serial is not None:
            raise RuntimeError(
                "reserved fallthrough helper was not consumed by branch lowering"
            )

        return change_2way_block_conditional_successor(
            blk,
            new_target,
            old_target=old_target,
            verify=False,
        )

    def _apply_fallthrough_change(
        self,
        blk: ida_hexrays.mblock_t,
        new_target: int,
        *,
        old_target: int,
        expected_helper_serial: int | None = None,
    ) -> bool:
        """Re-home a 2-way block's fallthrough via an adjacent NOP-goto helper.

        BLT_2WAY fallthrough must remain the physically-adjacent successor.
        To redirect the non-taken arm, insert a NOP block immediately after
        ``blk`` and repoint that helper to ``new_target``. Any blocks at or
        beyond the insertion point shift by +1, so update the mutation gateway
        before a later deferred modification reads a live MBA coordinate.
        """
        fallthrough_target = _get_fallthrough_successor_serial(blk)
        if fallthrough_target is None:
            logger.warning(
                "Block %d has no fallthrough successor to rewrite",
                blk.serial,
            )
            return False
        if int(fallthrough_target) != int(old_target):
            logger.warning(
                "Block %d fallthrough mismatch: expected old_target=%d but current fallthrough is %d",
                blk.serial,
                old_target,
                fallthrough_target,
            )
            return False
        if expected_helper_serial is None:
            raise RuntimeError(
                "fallthrough branch rewrite lacks reserved PlanBlockRef helper"
            )

        # ``new_target`` is already a live serial: _apply_single resolved it
        # through the mutation gateway before dispatching here.  Hold the live
        # block object across the helper insertion so Hex-Rays can update its
        # serial if the insertion precedes it.  Resolving the live serial a
        # second time is ambiguous when that number is also an original key
        # in the gateway (for example, an inserted helper shifts a live
        # target onto a serial that is also a distinct original-map key).
        new_target_blk = self.mba.get_mblock(int(new_target))
        if new_target_blk is None:
            logger.warning(
                "Block %d fallthrough rewrite target %d is not live",
                blk.serial,
                new_target,
            )
            return False

        old_qty = int(self.mba.qty)
        self._begin_patch_block_creation(expected_helper_serial)
        nop_blk = insert_nop_blk(blk)
        if nop_blk is None:
            logger.warning(
                "Failed to synthesize fallthrough helper for block %d",
                blk.serial,
            )
            return False

        insertion_serial = int(nop_blk.serial)
        self._record_serial_insertion(
            insertion_serial,
            old_qty,
            bound_serial=expected_helper_serial,
        )

        effective_new_target = int(new_target_blk.serial)
        logger.info(
            "Applying fallthrough rewrite on blk[%d]: old_target=%d helper=%d -> %d",
            blk.serial,
            old_target,
            insertion_serial,
            effective_new_target,
        )
        return change_1way_block_successor(
            nop_blk,
            int(effective_new_target),
            verify=False,
        )

    def _apply_convert_to_goto(
        self, blk: ida_hexrays.mblock_t, goto_target: int
    ) -> bool:
        """Connect a terminal block or collapse a 2-way block to a goto."""
        if blk.nsucc() == 0:
            return change_0way_block_successor(blk, goto_target, verify=False)
        return make_2way_block_goto(blk, goto_target, verify=False)

    def _apply_nway_null_tail_downgrade(
        self,
        blk: ida_hexrays.mblock_t,
        *,
        dispatcher_entry_serial: int | None,
    ) -> bool:
        if dispatcher_entry_serial is None:
            return False
        return downgrade_nway_null_tail_to_1way(
            blk,
            int(dispatcher_entry_serial),
            verify=False,
        )

    def _apply_nway_goto_type_downgrade(self, blk: ida_hexrays.mblock_t) -> bool:
        """Downgrade BLT_NWAY+m_goto+single-successor to BLT_1WAY."""
        tail = getattr(blk, "tail", None)
        if (
            blk.type != ida_hexrays.BLT_NWAY
            or tail is None
            or tail.opcode != ida_hexrays.m_goto
            or blk.nsucc() != 1
        ):
            return False
        blk.type = ida_hexrays.BLT_1WAY
        self.mba.mark_chains_dirty()
        return True

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
            "Instruction at EA %s not found in block %d", hex(insn_ea), blk.serial
        )
        return False

    def _apply_insn_nop(self, blk: ida_hexrays.mblock_t, insn_ea: int) -> bool:
        """NOP an instruction by its EA."""
        insn = blk.head
        while insn:
            if insn.ea == insn_ea:
                blk.make_nop(insn)
                blk.mark_lists_dirty()
                return True
            insn = insn.next

        logger.warning(
            "Instruction at EA %s not found in block %d", hex(insn_ea), blk.serial
        )
        return False

    def _payload_body_insns(self, blk: ida_hexrays.mblock_t) -> list:
        """Return non-NOP, non-goto payload instructions for ordinal addressing."""
        body = []
        insn = blk.head
        while insn is not None:
            opcode = int(getattr(insn, "opcode", -1))
            if opcode not in {
                int(ida_hexrays.m_nop),
                int(ida_hexrays.m_goto),
            }:
                body.append(insn)
            insn = getattr(insn, "next", None)
        return body

    def _apply_const_mov_and_nop_pair(
        self,
        blk: ida_hexrays.mblock_t,
        replacement_body_index: int | None,
        nop_body_index: int | None,
        const_value: int | None,
        replacement_dest: object | None,
        value_size: int | None,
    ) -> bool:
        """Replace one payload instruction with ``m_mov #const, dest`` and NOP another."""
        if (
            replacement_body_index is None
            or nop_body_index is None
            or const_value is None
            or replacement_dest is None
        ):
            logger.warning(
                "const_mov_and_nop_pair: incomplete payload for block %d",
                blk.serial,
            )
            return False
        body = self._payload_body_insns(blk)
        try:
            target = body[int(replacement_body_index)]
            paired_nop = body[int(nop_body_index)]
        except (IndexError, TypeError, ValueError):
            logger.warning(
                "const_mov_and_nop_pair: body index out of range for block %d "
                "(replace=%s nop=%s body_len=%d)",
                blk.serial,
                replacement_body_index,
                nop_body_index,
                len(body),
            )
            return False

        size = int(value_size or getattr(replacement_dest, "size", 0) or 4)
        mask = (1 << (size * 8)) - 1
        blk.make_nop(target)
        target.opcode = ida_hexrays.m_mov
        target.ea = int(getattr(self.mba, "entry_ea", 0) or 0)
        target.l = ida_hexrays.mop_t()
        target.l.make_number(
            int(const_value) & mask,
            size,
            int(getattr(self.mba, "entry_ea", 0) or 0),
        )
        target.r = ida_hexrays.mop_t()
        target.r.erase()
        target.d = ida_hexrays.mop_t(replacement_dest)
        blk.make_nop(paired_nop)
        blk.mark_lists_dirty()
        self.mba.mark_chains_dirty()
        logger.info(
            "CONST_MOV_AND_NOP_PAIR: blk[%d] replace=%d nop=%d value=0x%x",
            blk.serial,
            int(replacement_body_index),
            int(nop_body_index),
            int(const_value) & mask,
        )
        return True

    def _apply_zero_state_write(self, blk: ida_hexrays.mblock_t, insn_ea: int) -> bool:
        """Zero the source operand of a state variable write instruction.

        Finds ``m_mov #CONST, state_var`` at *insn_ea* and replaces ``#CONST``
        with ``#0``, keeping the instruction alive so the state variable is
        explicitly written to zero (killing entry-state liveness).
        """
        insn = blk.head
        while insn:
            if insn.ea == insn_ea:
                old_value = insn.l.nnn.value if insn.l.t == ida_hexrays.mop_n else 0
                insn.l.make_number(0, insn.l.size, insn.ea)
                logger.info(
                    "STATE_WRITE_ZERO: blk[%d]@0x%x — replaced state write "
                    "with m_mov #0 (was 0x%x)",
                    blk.serial,
                    insn_ea,
                    old_value,
                )
                return True
            insn = insn.next

        logger.warning(
            "Zero state write: instruction at EA %s not found in block %d",
            hex(insn_ea),
            blk.serial,
        )
        return False

    def _apply_promote_operand_to_scalar(
        self,
        blk: ida_hexrays.mblock_t,
        host_ea: int,
        host_opcode: int | None,
        operand_side: str | None,
    ) -> bool:
        """Promote a fused sub-instruction operand (mop_d) into its own
        standalone microcode instruction with a fresh kreg destination.

        See PromoteOperandToScalar dataclass for semantics. Recipe verified
        against hexrays.hpp by microcode-expert: kreg (not lvar), deep clone
        via copy ctor (not move), insert before host via insert_into_block
        with om=host.prev, prefer sub-insn EA, fallback to host EA.
        """
        if operand_side not in ("l", "r"):
            logger.warning(
                "promote_operand_to_scalar: invalid operand_side=%r at blk[%d]@0x%x",
                operand_side,
                blk.serial,
                host_ea,
            )
            return False

        host = blk.head
        prev = None
        while host is not None:
            if host.ea == host_ea and (
                host_opcode is None or host.opcode == host_opcode
            ):
                break
            prev = host
            host = host.next
        if host is None:
            logger.warning(
                "promote_operand_to_scalar: host insn at EA %s not found in block %d",
                hex(host_ea),
                blk.serial,
            )
            return False

        sub_mop = host.l if operand_side == "l" else host.r
        if sub_mop.t != ida_hexrays.mop_d or sub_mop.d is None:
            logger.warning(
                "promote_operand_to_scalar: blk[%d]@0x%x operand %s is not "
                "mop_d (t=%d) — nothing to promote",
                blk.serial,
                host_ea,
                operand_side,
                int(sub_mop.t),
            )
            return False

        sub_size = sub_mop.size
        sub_ea = sub_mop.d.ea
        if sub_ea == idaapi.BADADDR:
            sub_ea = host.ea

        kreg = self.mba.alloc_kreg(sub_size, True)
        if kreg == ida_hexrays.mr_none:
            logger.warning(
                "promote_operand_to_scalar: alloc_kreg(%d) returned mr_none "
                "at blk[%d]@0x%x",
                sub_size,
                blk.serial,
                host_ea,
            )
            return False

        # Deep clone via copy ctor — never move ownership of mop_d.d.
        promoted = ida_hexrays.minsn_t(sub_mop.d)
        promoted.ea = sub_ea
        promoted.d.erase()
        promoted.d.make_reg(kreg, sub_size)
        promoted.d.size = sub_size

        # insert_into_block(nm, om) inserts nm AFTER om; om=prev → before host.
        blk.insert_into_block(promoted, prev)

        # Replace the host's sub-operand with a register read of the kreg.
        sub_mop.make_reg(kreg, sub_size)

        # Re-seal use/def bookkeeping for the block.
        blk.mark_lists_dirty()

        logger.info(
            "PROMOTE_OPERAND_TO_SCALAR: blk[%d]@0x%x — hoisted operand "
            "%s (sub_ea=0x%x size=%d) into fresh kreg=%d",
            blk.serial,
            host_ea,
            operand_side,
            sub_ea,
            sub_size,
            kreg,
        )
        return True

    def _local_alias_base_mop(
        self,
        alias_token: str | None,
        base_token: str | None,
        *,
        size_hint: int = 0,
    ) -> object | None:
        alias = _canonical_local_var_token(alias_token)
        base = _canonical_local_var_token(base_token)
        if alias is None or base is None:
            return None
        qty = int(getattr(self.mba, "qty", 0) or 0)
        for serial in range(qty):
            try:
                blk = self.mba.get_mblock(serial)
            except Exception:
                continue
            if blk is None:
                continue
            insn = getattr(blk, "head", None)
            while insn is not None:
                if int(getattr(insn, "opcode", -1)) == int(ida_hexrays.m_mov):
                    dest = getattr(insn, "d", None)
                    source = getattr(insn, "l", None)
                    if (
                        _mop_local_var_token(dest) == alias
                        and _mop_local_var_token(source) == base
                        and "&(" in _mop_text(source)
                    ):
                        inner = getattr(source, "a", None)
                        base_mop = _copy_mop_for_alias_scalarization(inner)
                        if base_mop is None:
                            return None
                        if size_hint > 0:
                            with contextlib.suppress(Exception):
                                base_mop.size = int(size_hint)
                        return base_mop
                insn = getattr(insn, "next", None)
        return None

    def _replace_local_alias_load_mop(
        self,
        mop: object | None,
        *,
        alias_token: str,
        base_token: str,
        value_size: int | None = None,
    ) -> int:
        if mop is None:
            return 0
        nested = getattr(mop, "d", None)
        if nested is None:
            return 0
        changed = 0
        if int(getattr(nested, "opcode", -1)) == int(ida_hexrays.m_ldx):
            source = getattr(nested, "r", None)
            if _mop_local_var_token(source) == alias_token:
                if value_size is not None and value_size > 0:
                    try:
                        if int(getattr(mop, "size", 0) or 0) != int(value_size):
                            return 0
                    except Exception:
                        return 0
                if alias_token == base_token:
                    base_mop = _copy_mop_for_alias_scalarization(source)
                    base_mop = _apply_alias_scalarization_size_hint(
                        base_mop,
                        int(getattr(mop, "size", 0) or 0),
                    )
                else:
                    base_mop = self._local_alias_base_mop(
                        alias_token,
                        base_token,
                        size_hint=int(getattr(mop, "size", 0) or 0),
                    )
                if base_mop is None:
                    return 0
                try:
                    mop.assign(base_mop)
                    return 1
                except Exception:
                    return 0
        for side in ("l", "r", "d"):
            changed += self._replace_local_alias_load_mop(
                getattr(nested, side, None),
                alias_token=alias_token,
                base_token=base_token,
                value_size=value_size,
            )
        return changed

    def _apply_scalarize_local_alias_access(
        self,
        blk: ida_hexrays.mblock_t,
        host_ea: int | None,
        host_opcode: int | None,
        alias_token: str | None,
        base_token: str | None,
        host_text_sha1: str | None = None,
        value_size: int | None = None,
    ) -> bool:
        alias = _canonical_local_var_token(alias_token)
        base = _canonical_local_var_token(base_token)
        if alias is None or base is None:
            logger.warning(
                "scalarize_local_alias_access: invalid alias/base %r -> %r",
                alias_token,
                base_token,
            )
            return False
        host = blk.head
        while host is not None:
            if host.ea == host_ea and (
                host_opcode is None or host.opcode == host_opcode
            ):
                break
            host = host.next
        if host is None:
            logger.warning(
                "scalarize_local_alias_access: host insn at EA %s not found in block %d",
                hex(host_ea or 0),
                blk.serial,
            )
            return False
        if host_text_sha1:
            current_hash = _instruction_text_digest(_insn_text(host))
            if current_hash != host_text_sha1:
                logger.warning(
                    "scalarize_local_alias_access: live host text hash mismatch "
                    "at blk[%d]@%s expected=%s actual=%s",
                    blk.serial,
                    hex(host_ea or 0),
                    host_text_sha1,
                    current_hash,
                )
                return False

        changed = 0
        opcode = int(getattr(host, "opcode", -1))
        if opcode == int(ida_hexrays.m_ldx):
            source = getattr(host, "r", None)
            dest = getattr(host, "d", None)
            if _mop_local_var_token(source) == alias and dest is not None:
                if value_size is not None and value_size > 0:
                    try:
                        if int(getattr(dest, "size", 0) or 0) != int(value_size):
                            return False
                    except Exception:
                        return False
                if alias == base:
                    base_mop = _copy_mop_for_alias_scalarization(source)
                    base_mop = _apply_alias_scalarization_size_hint(
                        base_mop,
                        int(getattr(dest, "size", 0) or 0),
                    )
                else:
                    base_mop = self._local_alias_base_mop(
                        alias,
                        base,
                        size_hint=int(getattr(dest, "size", 0) or 0),
                    )
                if base_mop is None:
                    return False
                try:
                    saved_dest = ida_hexrays.mop_t()
                    saved_dest.assign(dest)
                    host.opcode = ida_hexrays.m_mov
                    host.l.assign(base_mop)
                    host.r.erase()
                    host.d.assign(saved_dest)
                    changed += 1
                except Exception:
                    return False
        elif opcode == int(ida_hexrays.m_stx):
            target = getattr(host, "d", None)
            source = getattr(host, "l", None)
            if _mop_local_var_token(target) == alias and source is not None:
                if value_size is not None and value_size > 0:
                    try:
                        if int(getattr(source, "size", 0) or 0) != int(value_size):
                            return False
                    except Exception:
                        return False
                if alias == base:
                    base_mop = _copy_mop_for_alias_scalarization(target)
                    base_mop = _apply_alias_scalarization_size_hint(
                        base_mop,
                        int(getattr(source, "size", 0) or 0),
                    )
                else:
                    base_mop = self._local_alias_base_mop(
                        alias,
                        base,
                        size_hint=int(getattr(source, "size", 0) or 0),
                    )
                if base_mop is None:
                    return False
                try:
                    saved_source = ida_hexrays.mop_t()
                    saved_source.assign(source)
                    host.opcode = ida_hexrays.m_mov
                    host.l.assign(saved_source)
                    host.r.erase()
                    host.d.assign(base_mop)
                    changed += 1
                except Exception:
                    return False

        for side in ("l", "r", "d"):
            changed += self._replace_local_alias_load_mop(
                getattr(host, side, None),
                alias_token=alias,
                base_token=base,
                value_size=value_size,
            )
        if changed <= 0:
            return False
        blk.mark_lists_dirty()
        logger.info(
            "SCALARIZE_LOCAL_ALIAS_ACCESS: blk[%d]@0x%x alias=%s base=%s rewrites=%d",
            blk.serial,
            int(host_ea or 0),
            alias,
            base,
            changed,
        )
        return True

    def _find_local_token_value_mop(
        self,
        local_token: str,
    ) -> object | None:
        token = _canonical_local_var_token(local_token)
        if token is None:
            return None
        qty = int(getattr(self.mba, "qty", 0) or 0)
        for serial in range(qty):
            try:
                blk = self.mba.get_mblock(serial)
            except Exception:
                continue
            if blk is None:
                continue
            insn = getattr(blk, "head", None)
            while insn is not None:
                for side in ("d", "l", "r"):
                    mop = getattr(insn, side, None)
                    if _mop_local_var_token(mop) != token:
                        continue
                    text = _mop_text(mop)
                    if "&(" in text or "[" in text:
                        continue
                    copied = _copy_mop_for_alias_scalarization(mop)
                    if copied is not None:
                        return copied
                insn = getattr(insn, "next", None)
        return None

    def _apply_retarget_output_store(
        self,
        blk: ida_hexrays.mblock_t,
        host_ea: int | None,
        host_opcode: int | None,
        alias_token: str | None,
        output_token: str | None,
        host_text_sha1: str | None = None,
        value_size: int | None = None,
    ) -> bool:
        alias = _canonical_local_var_token(alias_token)
        output = _canonical_local_var_token(output_token)
        if alias is None or output is None:
            logger.warning(
                "retarget_output_store: invalid alias/output %r -> %r",
                alias_token,
                output_token,
            )
            return False
        host = blk.head
        while host is not None:
            if host.ea == host_ea and (
                host_opcode is None or host.opcode == host_opcode
            ):
                break
            host = host.next
        if host is None:
            logger.warning(
                "retarget_output_store: host insn at EA %s not found in block %d",
                hex(host_ea or 0),
                blk.serial,
            )
            return False
        if host_text_sha1:
            current_hash = _instruction_text_digest(_insn_text(host))
            if current_hash != host_text_sha1:
                logger.warning(
                    "retarget_output_store: live host text hash mismatch "
                    "at blk[%d]@%s expected=%s actual=%s",
                    blk.serial,
                    hex(host_ea or 0),
                    host_text_sha1,
                    current_hash,
                )
                return False
        if int(getattr(host, "opcode", -1)) != int(ida_hexrays.m_stx):
            return False
        target = getattr(host, "d", None)
        source = getattr(host, "l", None)
        if _mop_local_var_token(target) != alias:
            return False
        if value_size is not None and value_size > 0:
            try:
                if int(getattr(source, "size", 0) or 0) != int(value_size):
                    return False
            except Exception:
                return False
        output_mop = self._find_local_token_value_mop(output)
        if output_mop is None:
            logger.warning(
                "retarget_output_store: output token %s not found in live MBA",
                output,
            )
            return False
        try:
            target.assign(output_mop)
        except Exception:
            return False
        blk.mark_lists_dirty()
        logger.info(
            "RETARGET_OUTPUT_STORE: blk[%d]@0x%x alias=%s output=%s",
            blk.serial,
            int(host_ea or 0),
            alias,
            output,
        )
        return True

    def _materialize_counter_bound_condition(
        self, condition_operand: object
    ) -> object | None:
        """Materialize a ``SyntheticCounterBoundCondition`` into a boolean ``mop_d``.

        Builds a ``setl``/``setb`` sub-instruction over the live counter (a stack
        slot via ``make_stkvar`` OR a register via ``make_reg``) versus the
        captured numeric bound, then wraps it as a ``mop_d`` so
        :meth:`_apply_lower_conditional_state_transition`'s ``m_jnz`` jumps to the
        loop-BODY (true) arm exactly when ``counter <cmp> bound``.

        Recognised by duck-typing (``bound`` + ``counter_stkoff``/``counter_reg``
        attributes) so the portable descriptor never has to be importable from
        this backend.
        """
        counter_stkoff = getattr(condition_operand, "counter_stkoff", None)
        counter_reg = getattr(condition_operand, "counter_reg", None)
        bound = getattr(condition_operand, "bound", None)
        if bound is None or (counter_stkoff is None and counter_reg is None):
            return None
        size = int(getattr(condition_operand, "counter_size", 4) or 4)
        signed = bool(getattr(condition_operand, "signed", True))
        safe_ea = int(getattr(self.mba, "entry_ea", 0) or 0) or 1
        try:
            cmp_insn = ida_hexrays.minsn_t(safe_ea)
            cmp_insn.opcode = ida_hexrays.m_setl if signed else ida_hexrays.m_setb
            cmp_insn.l = ida_hexrays.mop_t()
            if counter_reg is not None:
                cmp_insn.l.make_reg(int(counter_reg), size)
            else:
                cmp_insn.l.make_stkvar(self.mba, int(counter_stkoff))
                cmp_insn.l.size = size
            cmp_insn.r = ida_hexrays.mop_t()
            cmp_insn.r.make_number(int(bound) & ((1 << (8 * size)) - 1), size, safe_ea)
            cmp_insn.d = ida_hexrays.mop_t()
            cmp_insn.d.size = 1
            wrapped = ida_hexrays.mop_t()
            wrapped.create_from_insn(cmp_insn)
        except Exception as exc:  # noqa: BLE001 — synthesis is best-effort
            logger.warning(
                "conditional_state_transition: counter-bound synthesis failed: %s",
                exc,
            )
            return None
        if int(getattr(wrapped, "t", ida_hexrays.mop_z)) == int(ida_hexrays.mop_z):
            return None
        return wrapped

    def _materialize_register_nonzero_condition(
        self, condition_operand: object
    ) -> object | None:
        """Materialize a portable live-register boolean predicate."""
        predicate_reg = getattr(condition_operand, "predicate_reg", None)
        predicate_size = getattr(condition_operand, "predicate_size", None)
        if predicate_reg is None or predicate_size is None:
            return None
        try:
            result = ida_hexrays.mop_t()
            result.make_reg(int(predicate_reg), int(predicate_size))
        except Exception as exc:  # noqa: BLE001 - synthesis is best-effort
            logger.warning(
                "conditional_state_transition: register predicate synthesis failed: %s",
                exc,
            )
            return None
        if int(getattr(result, "t", ida_hexrays.mop_z)) == int(ida_hexrays.mop_z):
            return None
        return result

    def _materialize_stack_value_equals_condition(
        self, condition_operand: object
    ) -> object | None:
        """Materialize a proven ``stack_cell == constant`` boolean."""
        stack_stkoff = getattr(condition_operand, "stack_stkoff", None)
        stack_size = getattr(condition_operand, "stack_size", None)
        value = getattr(condition_operand, "value", None)
        if stack_stkoff is None or stack_size is None or value is None:
            return None
        size = int(stack_size)
        if size <= 0:
            return None
        safe_ea = int(getattr(self.mba, "entry_ea", 0) or 0) or 1
        try:
            compare = ida_hexrays.minsn_t(safe_ea)
            compare.opcode = ida_hexrays.m_setz
            compare.l = ida_hexrays.mop_t()
            compare.l.make_stkvar(self.mba, int(stack_stkoff))
            compare.l.size = size
            compare.r = ida_hexrays.mop_t()
            compare.r.make_number(
                int(value) & ((1 << (8 * size)) - 1),
                size,
                safe_ea,
            )
            compare.d = ida_hexrays.mop_t()
            compare.d.size = 1
            wrapped = ida_hexrays.mop_t()
            wrapped.create_from_insn(compare)
        except Exception as exc:  # noqa: BLE001 - synthesis is best-effort
            logger.warning(
                "conditional_state_transition: stack-value synthesis failed: %s",
                exc,
            )
            return None
        if int(getattr(wrapped, "t", ida_hexrays.mop_z)) == int(ida_hexrays.mop_z):
            return None
        return wrapped

    def _materialize_register_state_write(
        self,
        *,
        ea: int,
        state_register: int,
        state_size: int,
        state_value: int,
    ) -> ida_hexrays.minsn_t:
        """Build ``m_mov #state, register`` for one conditional arm."""
        size = int(state_size)
        register = int(state_register)
        if size <= 0 or register < 0:
            raise ValueError(
                "state register assignments require positive size and register"
            )
        mask = (1 << (size * 8)) - 1
        assignment = ida_hexrays.minsn_t(int(ea))
        assignment.opcode = ida_hexrays.m_mov
        assignment.l.make_number(int(state_value) & mask, size, int(ea))
        assignment.d.make_reg(register, size)
        return assignment

    def _materialize_condition_mop(
        self, condition_operand: object | None
    ) -> object | None:
        """Clone a proof-supplied condition operand into an owned ``mop_t``."""
        if condition_operand is None:
            return None
        if (
            getattr(condition_operand, "stack_stkoff", None) is not None
            and getattr(condition_operand, "stack_size", None) is not None
            and getattr(condition_operand, "value", None) is not None
            and not callable(getattr(condition_operand, "to_mop", None))
        ):
            return self._materialize_stack_value_equals_condition(condition_operand)
        if (
            getattr(condition_operand, "predicate_reg", None) is not None
            and getattr(condition_operand, "predicate_size", None) is not None
            and not callable(getattr(condition_operand, "to_mop", None))
        ):
            return self._materialize_register_nonzero_condition(condition_operand)
        if (
            (
                getattr(condition_operand, "counter_stkoff", None) is not None
                or getattr(condition_operand, "counter_reg", None) is not None
            )
            and getattr(condition_operand, "bound", None) is not None
            and not callable(getattr(condition_operand, "to_mop", None))
        ):
            return self._materialize_counter_bound_condition(condition_operand)
        raw_operand = condition_operand
        to_mop = getattr(raw_operand, "to_mop", None)
        if callable(to_mop):
            try:
                raw_operand = to_mop()
            except Exception as exc:
                logger.warning("conditional_state_transition: to_mop failed: %s", exc)
                return None
        else:
            raw_operand = getattr(raw_operand, "owned_mop", raw_operand)
        try:
            copied = ida_hexrays.mop_t()
            copied.assign(raw_operand)
        except Exception as exc:
            logger.warning(
                "conditional_state_transition: could not clone condition operand %r: %s",
                type(condition_operand).__name__,
                exc,
            )
            return None
        if int(getattr(copied, "t", ida_hexrays.mop_z)) == int(ida_hexrays.mop_z):
            return None
        return copied

    def _find_exact_register_state_write(
        self,
        *,
        write_ea: int,
        state_register: int,
        state_size: int,
        state_value: int,
    ) -> tuple[ida_hexrays.mblock_t, ida_hexrays.minsn_t] | None:
        """Find one exact microcode state write that an arm helper will hoist."""
        mask = (1 << (8 * int(state_size))) - 1
        matches: list[tuple[ida_hexrays.mblock_t, ida_hexrays.minsn_t]] = []
        for serial in range(int(self.mba.qty)):
            owner = self.mba.get_mblock(serial)
            instruction = owner.head
            while instruction is not None:
                if (
                    int(instruction.ea) == int(write_ea)
                    and int(instruction.opcode) == int(ida_hexrays.m_mov)
                    and int(instruction.d.t) == int(ida_hexrays.mop_r)
                    and int(instruction.d.r) == int(state_register)
                    and int(instruction.d.size) == int(state_size)
                    and int(instruction.l.t) == int(ida_hexrays.mop_n)
                    and int(instruction.l.size) == int(state_size)
                    and (int(instruction.l.nnn.value) & mask)
                    == (int(state_value) & mask)
                ):
                    matches.append((owner, instruction))
                if instruction is owner.tail:
                    break
                instruction = instruction.next
        return matches[0] if len(matches) == 1 else None

    def _apply_materialize_zero_way_conditional(
        self,
        blk: ida_hexrays.mblock_t,
        *,
        predicate_ea: int | None,
        taken_target_serial: int | None,
        fallthrough_target_serial: int | None,
    ) -> bool:
        """Bind both CFG arms of a generated zero-way ``m_jcnd``.

        The branch instruction itself is native microcode evidence.  Keep its
        opcode and condition operands unchanged; only replace the not-yet-bound
        ``mop_v`` destination with a block reference and construct the verifier
        required adjacent fallthrough helper.
        """
        if (
            predicate_ea is None
            or taken_target_serial is None
            or fallthrough_target_serial is None
            or blk.tail is None
            or int(blk.nsucc()) != 0
            or int(blk.tail.ea) != int(predicate_ea)
            or not ida_hexrays.is_mcode_jcond(int(blk.tail.opcode))
            or getattr(blk.tail, "d", None) is None
            or int(blk.tail.d.t) != int(ida_hexrays.mop_v)
        ):
            logger.warning(
                "materialize_zero_way_conditional: source blk[%d] no longer "
                "matches generated predicate at %s",
                int(blk.serial),
                None if predicate_ea is None else hex(int(predicate_ea)),
            )
            return False

        taken_serial = self._resolve_serial(int(taken_target_serial))
        fallthrough_serial = self._resolve_serial(int(fallthrough_target_serial))
        if (
            taken_serial is None
            or fallthrough_serial is None
            or int(taken_serial) == int(fallthrough_serial)
        ):
            return False
        taken_blk = self.mba.get_mblock(int(taken_serial))
        fallthrough_blk = self.mba.get_mblock(int(fallthrough_serial))
        if taken_blk is None or fallthrough_blk is None:
            return False

        helper_serial = self._build_fallthrough_goto_helper(
            blk,
            fallthrough_blk,
        )
        if helper_serial is None:
            return False

        # The helper insertion can shift both existing targets.  Hold block
        # objects across it and consume their live serials only now.
        live_taken_serial = int(taken_blk.serial)
        live_fallthrough_serial = int(fallthrough_blk.serial)
        live_helper_serial = int(helper_serial)
        if live_taken_serial == live_helper_serial:
            return False

        blk.tail.d.make_blkref(live_taken_serial)
        blk.flags &= ~ida_hexrays.MBL_GOTO
        blk.type = ida_hexrays.BLT_2WAY
        for stale in [int(value) for value in blk.succset]:
            blk.succset._del(stale)
            stale_blk = self.mba.get_mblock(stale)
            if stale_blk is not None:
                stale_blk.predset._del(int(blk.serial))
        for successor in (live_helper_serial, live_taken_serial):
            blk.succset.push_back(int(successor))
            successor_blk = self.mba.get_mblock(int(successor))
            if successor_blk is not None and int(blk.serial) not in [
                int(pred) for pred in successor_blk.predset
            ]:
                successor_blk.predset.push_back(int(blk.serial))
                successor_blk.mark_lists_dirty()
        blk.mark_lists_dirty()
        self.mba.mark_chains_dirty()
        logger.info(
            "MATERIALIZE_ZERO_WAY_CONDITIONAL: blk[%d] predicate=0x%x "
            "taken=%d fallthrough=%d helper=%d",
            int(blk.serial),
            int(predicate_ea),
            live_taken_serial,
            live_fallthrough_serial,
            live_helper_serial,
        )
        return True

    def _apply_materialize_zero_way_goto(
        self,
        blk: ida_hexrays.mblock_t,
        *,
        predicate_ea: int | None,
        target_serial: int | None,
    ) -> bool:
        """Replace one exact generated zero-way transfer with a direct edge.

        This helper is used on a staged copy.  The original zero-way
        ``m_jcnd`` remains live until the copy contains both the replacement
        ``m_goto`` and its reciprocal CFG edge, after which the staged gateway
        redirects the original predecessors in one commit.
        """
        if (
            predicate_ea is None
            or target_serial is None
            or blk.tail is None
            or int(blk.nsucc()) != 0
            or int(blk.tail.ea) != int(predicate_ea)
            or not (
                int(blk.tail.opcode)
                in {
                    int(ida_hexrays.m_ijmp),
                    int(ida_hexrays.m_call),
                    int(ida_hexrays.m_icall),
                }
                or (
                    ida_hexrays.is_mcode_jcond(int(blk.tail.opcode))
                    and getattr(blk.tail, "d", None) is not None
                    and int(blk.tail.d.t)
                    in {
                        int(ida_hexrays.mop_v),
                        int(ida_hexrays.mop_b),
                    }
                )
            )
        ):
            logger.warning(
                "materialize_zero_way_goto: source blk[%d] no longer "
                "matches generated predicate at %s",
                int(blk.serial),
                None if predicate_ea is None else hex(int(predicate_ea)),
            )
            return False

        # ``new_target`` is resolved before staging (and before sequential
        # dispatch).  Resolving it again here can incorrectly apply a second
        # planned-to-live serial shift after another mutation inserted blocks.
        target = self.mba.get_mblock(int(target_serial))
        if target is None:
            return False

        insert_goto_instruction(
            blk,
            int(target.serial),
            nop_previous_instruction=True,
            instruction_ea=int(predicate_ea),
        )
        blk.type = int(ida_hexrays.BLT_1WAY)
        blk.flags |= int(ida_hexrays.MBL_GOTO)
        if not any(
            int(instruction.opcode)
            in {int(ida_hexrays.m_call), int(ida_hexrays.m_icall)}
            for instruction in self._block_instructions(blk)
        ):
            blk.flags &= ~int(ida_hexrays.MBL_CALL)
        for stale in tuple(int(value) for value in blk.succset):
            blk.succset._del(stale)
            stale_block = self.mba.get_mblock(stale)
            if stale_block is not None and int(blk.serial) in {
                int(predecessor) for predecessor in stale_block.predset
            }:
                stale_block.predset._del(int(blk.serial))
                stale_block.mark_lists_dirty()
        blk.succset.push_back(int(target.serial))
        if int(blk.serial) not in {int(predecessor) for predecessor in target.predset}:
            target.predset.push_back(int(blk.serial))
        blk.mark_lists_dirty()
        target.mark_lists_dirty()
        self.mba.mark_chains_dirty()
        logger.info(
            "MATERIALIZE_ZERO_WAY_GOTO: blk[%d] predicate=0x%x target=%d",
            int(blk.serial),
            int(predicate_ea),
            int(target.serial),
        )
        return True

    def _apply_lower_conditional_state_transition(
        self,
        blk: ida_hexrays.mblock_t,
        *,
        old_dispatcher_serial: int | None,
        rewrite_from_ea: int | None,
        condition_operand: object | None,
        false_target_serial: int | None,
        true_target_serial: int | None,
        state_register: int | None = None,
        state_size: int | None = None,
        false_state: int | None = None,
        true_state: int | None = None,
        false_state_write_ea: int | None = None,
        true_state_write_ea: int | None = None,
    ) -> bool:
        """Lower a proven conditional state update into explicit 2-way topology."""
        if (
            old_dispatcher_serial is None
            or rewrite_from_ea is None
            or false_target_serial is None
            or true_target_serial is None
        ):
            logger.warning(
                "conditional_state_transition: incomplete proof for block %d",
                blk.serial,
            )
            return False
        state_fields = (state_register, state_size, false_state, true_state)
        has_arm_state_writes = all(value is not None for value in state_fields)
        if (
            any(value is not None for value in state_fields)
            and not has_arm_state_writes
        ):
            logger.warning(
                "conditional_state_transition: partial arm-state proof for block %d",
                blk.serial,
            )
            return False
        if has_arm_state_writes and (int(state_register) < 0 or int(state_size) <= 0):
            logger.warning(
                "conditional_state_transition: invalid arm-state register for block %d",
                blk.serial,
            )
            return False
        hoisted_writes: list[tuple[ida_hexrays.mblock_t, ida_hexrays.minsn_t]] = []
        for write_ea, state_value in (
            (false_state_write_ea, false_state),
            (true_state_write_ea, true_state),
        ):
            if write_ea is None:
                continue
            if not has_arm_state_writes:
                return False
            match = self._find_exact_register_state_write(
                write_ea=int(write_ea),
                state_register=int(state_register),
                state_size=int(state_size),
                state_value=int(state_value),
            )
            if match is None:
                logger.warning(
                    "conditional_state_transition: arm-state write 0x%x not unique",
                    int(write_ea),
                )
                return False
            hoisted_writes.append(match)
        false_target = self._resolve_serial(int(false_target_serial))
        true_target = self._resolve_serial(int(true_target_serial))
        old_dispatcher = self._resolve_serial(int(old_dispatcher_serial))
        if false_target is None or true_target is None or old_dispatcher is None:
            logger.info(
                "conditional_state_transition diagnostic: unresolved serial "
                "source=blk%d@0x%x old=%s false=%s true=%s",
                int(blk.serial),
                int(blk.start),
                old_dispatcher_serial,
                false_target_serial,
                true_target_serial,
            )
            return False
        if not _is_live_block_serial(
            self.mba, false_target
        ) or not _is_live_block_serial(self.mba, true_target):
            logger.warning(
                "conditional_state_transition: target missing for block %d false=%s true=%s",
                blk.serial,
                false_target,
                true_target,
            )
            return False
        current_successors = tuple(int(successor) for successor in blk.succset)
        if int(blk.nsucc()) not in (0, 1, 2) or (
            current_successors and int(old_dispatcher) not in current_successors
        ):
            logger.warning(
                "conditional_state_transition: block %d expected dispatcher successor %d, succs=%s",
                blk.serial,
                old_dispatcher,
                list(current_successors),
            )
            return False
        rewrite_insn = blk.head
        while rewrite_insn is not None:
            if int(getattr(rewrite_insn, "ea", -1)) == int(rewrite_from_ea):
                break
            rewrite_insn = rewrite_insn.next
        if rewrite_insn is None:
            logger.warning(
                "conditional_state_transition: rewrite EA %s not found in block %d",
                hex(int(rewrite_from_ea)),
                blk.serial,
            )
            return False

        preserve_live_predicate = bool(
            getattr(condition_operand, "preserve_live_predicate", False)
        )
        synthetic_register_comparison = (
            condition_operand
            if isinstance(condition_operand, _SyntheticRegisterComparisonCondition)
            else None
        )
        preserved_branch = None
        true_is_taken = True
        condition_mop = None
        if preserve_live_predicate:
            predicate_ea = getattr(condition_operand, "predicate_ea", None)
            marker_true_is_taken = getattr(condition_operand, "true_is_taken", None)
            if (
                predicate_ea is None
                or int(predicate_ea) != int(rewrite_from_ea)
                or marker_true_is_taken not in (True, False)
                or blk.tail is None
                or int(blk.tail.ea) != int(rewrite_from_ea)
                or int(blk.tail.opcode) != int(rewrite_insn.opcode)
                or not ida_hexrays.is_mcode_jcond(int(rewrite_insn.opcode))
                or int(blk.nsucc()) != 2
            ):
                logger.warning(
                    "conditional_state_transition: live predicate proof "
                    "does not match block %d at 0x%x",
                    blk.serial,
                    int(rewrite_from_ea),
                )
                return False
            preserved_branch = ida_hexrays.minsn_t(rewrite_insn)
            true_is_taken = bool(marker_true_is_taken)
        elif synthetic_register_comparison is None:
            condition_mop = self._materialize_condition_mop(condition_operand)
            if condition_mop is None:
                logger.info(
                    "conditional_state_transition diagnostic: condition clone "
                    "failed source=blk%d@0x%x type=%s",
                    int(blk.serial),
                    int(blk.start),
                    type(condition_operand).__name__,
                )
                return False

        safe_ea = int(rewrite_from_ea)
        if safe_ea == idaapi.BADADDR:
            safe_ea = int(getattr(self.mba, "entry_ea", 0) or 0) or 1

        # Inserting the fall-through helper shifts the serials of every block
        # after the guard, so hold the targets as mblock OBJECTS and re-read
        # their serials AFTER the insert.  Hex-Rays verify (INTERR 50860)
        # requires a 2-way block's fall-through (succset[0]) to be the
        # PHYSICALLY-next block; ``false_target`` is an arbitrary handler, so
        # synthesize a fall-through NOP-goto helper directly after the guard
        # (``copy_block_keep`` inserts before ``serial + 1``) that gotos the
        # false arm, and wire ``succset = [helper, taken]``.
        true_blk = self.mba.get_mblock(int(true_target))
        false_blk = self.mba.get_mblock(int(false_target))
        source_serial_before_insertion = int(blk.serial)
        source_start_ea = int(blk.start)
        source_instruction_ea = int(rewrite_insn.ea)
        true_serial_before_insertion = (
            int(true_blk.serial) if true_blk is not None else -1
        )
        true_start_ea = int(true_blk.start) if true_blk is not None else idaapi.BADADDR
        true_instruction_ea = (
            None if true_blk is None or true_blk.head is None else int(true_blk.head.ea)
        )
        false_serial_before_insertion = (
            int(false_blk.serial) if false_blk is not None else -1
        )
        false_start_ea = (
            int(false_blk.start) if false_blk is not None else idaapi.BADADDR
        )
        false_instruction_ea = (
            None
            if false_blk is None or false_blk.head is None
            else int(false_blk.head.ea)
        )
        logger.info(
            "conditional target identity before helper: true=blk%d@0x%x %s "
            "false=blk%d@0x%x %s",
            int(true_blk.serial),
            int(true_blk.start),
            tuple(
                (int(i.ea), int(i.opcode)) for i in self._block_instructions(true_blk)
            ),
            int(false_blk.serial),
            int(false_blk.start),
            tuple(
                (int(i.ea), int(i.opcode)) for i in self._block_instructions(false_blk)
            ),
        )
        taken_target = int(true_target if true_is_taken else false_target)
        taken_state = true_state if true_is_taken else false_state
        fallthrough_state = false_state if true_is_taken else true_state
        taken_blk = self.mba.get_mblock(taken_target)
        fallthrough_blk = false_blk if true_is_taken else true_blk
        if (
            true_blk is None
            or false_blk is None
            or taken_blk is None
            or fallthrough_blk is None
        ):
            logger.info(
                "conditional_state_transition diagnostic: target object missing "
                "source=blk%d@0x%x true=%s false=%s taken=%s fallthrough=%s",
                int(blk.serial),
                int(blk.start),
                true_blk,
                false_blk,
                taken_blk,
                fallthrough_blk,
            )
            return False
        taken_helper_serial = None
        if has_arm_state_writes:
            taken_helper_serial = self._build_fallthrough_goto_helper(
                blk,
                taken_blk,
                state_register=int(state_register),
                state_size=int(state_size),
                state_value=int(taken_state),
            )
            if taken_helper_serial is None:
                logger.info(
                    "conditional_state_transition diagnostic: taken helper failed "
                    "source=blk%d@0x%x",
                    int(blk.serial),
                    int(blk.start),
                )
                return False
            blk = self._reacquire_block_after_insertion(
                source_serial_before_insertion,
                source_start_ea,
                exact_instruction_ea=source_instruction_ea,
                insertion_serial=int(taken_helper_serial),
            )
            true_blk = self._reacquire_block_after_insertion(
                true_serial_before_insertion,
                true_start_ea,
                exact_instruction_ea=true_instruction_ea,
                insertion_serial=int(taken_helper_serial),
            )
            false_blk = self._reacquire_block_after_insertion(
                false_serial_before_insertion,
                false_start_ea,
                exact_instruction_ea=false_instruction_ea,
                insertion_serial=int(taken_helper_serial),
            )
            if blk is None or true_blk is None or false_blk is None:
                return False
            fallthrough_blk = false_blk if true_is_taken else true_blk
            source_serial_before_insertion = int(blk.serial)
            true_serial_before_insertion = int(true_blk.serial)
            false_serial_before_insertion = int(false_blk.serial)
        first_succ = self._build_fallthrough_goto_helper(
            blk,
            fallthrough_blk,
            state_register=(int(state_register) if has_arm_state_writes else None),
            state_size=(int(state_size) if has_arm_state_writes else None),
            state_value=(int(fallthrough_state) if has_arm_state_writes else None),
        )
        if first_succ is None:
            logger.info(
                "conditional_state_transition diagnostic: fallthrough helper failed "
                "source=blk%d@0x%x target=blk%d@0x%x",
                int(blk.serial),
                int(blk.start),
                int(fallthrough_blk.serial),
                int(fallthrough_blk.start),
            )
            return False
        blk = self._reacquire_block_after_insertion(
            source_serial_before_insertion,
            source_start_ea,
            exact_instruction_ea=source_instruction_ea,
            insertion_serial=int(first_succ),
        )
        true_blk = self._reacquire_block_after_insertion(
            true_serial_before_insertion,
            true_start_ea,
            exact_instruction_ea=true_instruction_ea,
            insertion_serial=int(first_succ),
        )
        false_blk = self._reacquire_block_after_insertion(
            false_serial_before_insertion,
            false_start_ea,
            exact_instruction_ea=false_instruction_ea,
            insertion_serial=int(first_succ),
        )
        if blk is None or true_blk is None or false_blk is None:
            return False
        logger.info(
            "conditional target identity after helper: source=blk%d@0x%x %s "
            "true=blk%d@0x%x %s false=blk%d@0x%x %s",
            int(blk.serial),
            int(blk.start),
            tuple((int(i.ea), int(i.opcode)) for i in self._block_instructions(blk)),
            int(true_blk.serial),
            int(true_blk.start),
            tuple(
                (int(i.ea), int(i.opcode)) for i in self._block_instructions(true_blk)
            ),
            int(false_blk.serial),
            int(false_blk.start),
            tuple(
                (int(i.ea), int(i.opcode)) for i in self._block_instructions(false_blk)
            ),
        )
        taken_blk = true_blk if true_is_taken else false_blk
        fallthrough_blk = false_blk if true_is_taken else true_blk
        if taken_helper_serial is None:
            taken_serial = int(taken_blk.serial)
        else:
            current_taken_helper_serial = self._resolve_serial(int(taken_helper_serial))
            if current_taken_helper_serial is None:
                return False
            taken_serial = int(current_taken_helper_serial)

        rewrite_insn = blk.head
        while rewrite_insn is not None:
            if int(rewrite_insn.ea) == source_instruction_ea:
                break
            rewrite_insn = rewrite_insn.next
        if rewrite_insn is None:
            return False
        cursor = rewrite_insn
        while cursor is not None:
            next_insn = cursor.next
            blk.remove_from_block(cursor)
            cursor = next_insn

        if preserved_branch is not None:
            branch = preserved_branch
            branch.d.make_blkref(int(taken_serial))
        elif synthetic_register_comparison is not None:
            branch = ida_hexrays.minsn_t(safe_ea)
            branch.opcode = int(synthetic_register_comparison.branch_opcode)
            branch.l = ida_hexrays.mop_t()
            branch.l.make_reg(
                int(synthetic_register_comparison.predicate_register),
                int(synthetic_register_comparison.predicate_size),
            )
            branch.r = ida_hexrays.mop_t()
            branch.r.make_number(
                int(synthetic_register_comparison.predicate_constant),
                int(synthetic_register_comparison.predicate_size),
                safe_ea,
            )
            branch.d = ida_hexrays.mop_t()
            branch.d.make_blkref(int(taken_serial))
        else:
            condition_size = int(getattr(condition_mop, "size", 0) or 1)
            branch = ida_hexrays.minsn_t(safe_ea)
            branch.opcode = ida_hexrays.m_jnz
            branch.l = ida_hexrays.mop_t()
            branch.l.assign(condition_mop)
            branch.r = ida_hexrays.mop_t()
            branch.r.make_number(0, condition_size, safe_ea)
            branch.d = ida_hexrays.mop_t()
            branch.d.make_blkref(int(taken_serial))
        blk.insert_into_block(branch, blk.tail)
        blk.flags &= ~ida_hexrays.MBL_GOTO
        blk.type = ida_hexrays.BLT_2WAY

        # Drop the stale dispatcher edge and install the layout-valid 2-way set.
        for s in [int(x) for x in blk.succset]:
            blk.succset._del(s)
            sblk = self.mba.get_mblock(s)
            if sblk is not None:
                sblk.predset._del(blk.serial)
                if sblk.serial != self.mba.qty - 1:
                    sblk.mark_lists_dirty()
        for new_succ in (int(first_succ), int(taken_serial)):
            blk.succset.push_back(new_succ)
            nblk = self.mba.get_mblock(new_succ)
            if nblk is not None and blk.serial not in [int(p) for p in nblk.predset]:
                nblk.predset.push_back(blk.serial)
                if nblk.serial != self.mba.qty - 1:
                    nblk.mark_lists_dirty()
        for owner, instruction in hoisted_writes:
            owner.make_nop(instruction)
            owner.mark_lists_dirty()
        blk.mark_lists_dirty()
        self.mba.mark_chains_dirty()
        logger.info(
            "LOWER_CONDITIONAL_STATE_TRANSITION: blk[%d] old=%d taken=%d "
            "(fallthrough_helper=%d) ea=0x%x",
            blk.serial,
            old_dispatcher,
            taken_serial,
            int(first_succ),
            int(rewrite_from_ea),
        )
        if preserved_branch is not None:
            register_resolver_proven_live_predicate(
                self.mba,
                int(rewrite_from_ea),
            )
        # Diagnostic-only provenance: the lowered 2-way replaces a single
        # state-write-to-dispatcher edge, so the surviving snapshot shows only a
        # 1-way handler with no constant state write. Persist the (source,
        # true_arm, false_arm) lowering so the read-only transfer-map extractor
        # can re-derive the two next-states for this conditional. The fall-
        # through HELPER is a synthetic NOP-goto, so record the REAL false-arm
        # handler block (re-read after the serial-shifting insert), not the
        # helper. This does NOT change CFG topology — the rewire above did.
        try:
            from d810.core.observability_cfg import observe_cfg_provenance_latest

            false_handler_serial = int(false_blk.serial)
            true_path_serial = int(taken_serial) if true_is_taken else int(first_succ)
            # Late-binding variant: this lowering can fire AFTER the last
            # captured snapshot, so bind the row to the latest snapshot for the
            # func directly rather than buffering for a "next snapshot" drain
            # that may never come.
            observe_cfg_provenance_latest(
                func_ea=int(getattr(self.mba, "entry_ea", 0) or 0),
                pass_name="deferred_modifier",
                action="LOWER_CONDITIONAL_STATE_TRANSITION",
                block_serial=int(blk.serial),
                target_serial=true_path_serial,
                reason="lower_conditional_state_transition",
                extra={
                    "true_target": true_path_serial,
                    "false_target": false_handler_serial,
                    "fallthrough_helper": int(first_succ),
                    "old_dispatcher": int(old_dispatcher),
                    "rewrite_from_ea": int(rewrite_from_ea),
                    "state_register": state_register,
                    "state_size": state_size,
                    "false_state": false_state,
                    "true_state": true_state,
                    "false_state_write_ea": false_state_write_ea,
                    "true_state_write_ea": true_state_write_ea,
                },
                mba=self.mba,
            )
        except Exception:
            pass
        return True

    def _reacquire_block_after_insertion(
        self,
        serial_before_insertion: int,
        start_ea: int,
        *,
        exact_instruction_ea: int | None = None,
        insertion_serial: int | None = None,
    ) -> ida_hexrays.mblock_t | None:
        """Reacquire an ``mblock_t`` after MBA storage has been reallocated."""
        if insertion_serial is not None:
            expected_serial = int(serial_before_insertion) + int(
                int(serial_before_insertion) >= int(insertion_serial)
            )
            if _is_live_block_serial(self.mba, expected_serial):
                expected = self.mba.get_mblock(expected_serial)
                has_expected_instruction = exact_instruction_ea is None or any(
                    int(instruction.ea) == int(exact_instruction_ea)
                    for instruction in self._block_instructions(expected)
                )
                if (
                    expected is not None
                    and int(expected.start) == int(start_ea)
                    and has_expected_instruction
                ):
                    return expected
        if exact_instruction_ea is not None:
            exact_matches = tuple(
                candidate
                for serial in range(int(self.mba.qty))
                for candidate in (self.mba.get_mblock(serial),)
                if candidate is not None
                and any(
                    int(instruction.ea) == int(exact_instruction_ea)
                    for instruction in self._block_instructions(candidate)
                )
            )
            if len(exact_matches) == 1:
                return exact_matches[0]
        resolved_serial = self._resolve_serial(int(serial_before_insertion))
        if resolved_serial is not None:
            candidate = self.mba.get_mblock(int(resolved_serial))
            if candidate is not None and int(candidate.start) == int(start_ea):
                return candidate
        matches = tuple(
            candidate
            for serial in range(int(self.mba.qty))
            for candidate in (self.mba.get_mblock(serial),)
            if candidate is not None and int(candidate.start) == int(start_ea)
        )
        instruction_backed = tuple(
            candidate
            for candidate in matches
            if candidate.head is not None
            and int(candidate.type) != int(ida_hexrays.BLT_XTRN)
        )
        if len(instruction_backed) == 1:
            return instruction_backed[0]
        return matches[0] if len(matches) == 1 else None

    def _build_fallthrough_goto_helper(
        self,
        blk: ida_hexrays.mblock_t,
        target_blk: ida_hexrays.mblock_t,
        *,
        state_register: int | None = None,
        state_size: int | None = None,
        state_value: int | None = None,
        created_handle: MbaBlockHandle | None = None,
        target_handle: MbaBlockHandle | None = None,
        creation_plan_ref: PlanBlockRef | None = None,
    ) -> int | None:
        """Create an empty 1-way goto block immediately after ``blk``.

        The adjacent helper materializes physical fallthrough for either a
        one-way call block or a two-way conditional.  ``mba.insert_block``
        inserts before ``blk.serial + 1``, so the helper becomes ``blk.nextb``
        without cloning a source body whose fictitious instruction addresses
        belong to another logical block.
        """
        mba = blk.mba
        gateway = self._mutation_gateway
        if gateway is None:
            raise RuntimeError(
                "fallthrough helper insertion requires a mutation gateway"
            )
        target_serial_before_insertion = int(target_blk.serial)
        target_handle = target_handle or gateway.identity_index.handle_for_serial(
            target_serial_before_insertion
        )
        state_fields = (state_register, state_size, state_value)
        if target_handle is None or (
            any(value is not None for value in state_fields)
            and not all(value is not None for value in state_fields)
        ):
            return None
        assignment_ea = (
            int(blk.tail.ea) if blk.tail is not None else int(self.mba.entry_ea)
        )
        old_qty = int(mba.qty)
        if gateway.current_transaction_attempt is not None:
            gateway._record_cfg_mutation_started()
        nop_block = mba.insert_block(int(blk.serial) + 1)
        if nop_block is None:
            return None
        if creation_plan_ref is None:
            self._record_serial_insertion(
                int(nop_block.serial),
                old_qty,
                created=created_handle,
            )
        else:
            attempt = gateway.current_transaction_attempt
            if attempt is None:
                raise SemanticEdgeOperationRejected(
                    "planned fallthrough helper has no transaction attempt"
                )
            gateway.bind_reserved_plan_block(
                attempt,
                creation_plan_ref,
                insertion_serial=int(nop_block.serial),
                returned_serial=int(nop_block.serial),
            )
        if (
            nop_block.head is not None
            or nop_block.tail is not None
            or int(nop_block.nsucc()) != 0
            or int(nop_block.npred()) != 0
        ):
            raise SemanticEdgeOperationRejected(
                "Hex-Rays adjacent block insertion returned non-empty structure"
            )
        # The helper is transaction-owned synthetic structure, not another
        # native instance of the source.  Give it verifier-safe metadata
        # before it becomes instruction-bearing: entry roots can have an empty
        # [start, end) range, which otherwise trips verify.cpp 50870 after the
        # helper receives its explicit goto.
        self.configure_block_now(
            nop_block,
            flags=(int(nop_block.flags) & int(ida_hexrays.MBL_PUSH))
            | int(ida_hexrays.MBL_KEEP)
            | int(ida_hexrays.MBL_FAKE),
            start_ea=int(mba.entry_ea),
            end_ea=int(mba.entry_ea) + 1,
        )
        logger.info(
            "fallthrough helper insertion diagnostic: source=blk%d@0x%x "
            "returned=blk%d@0x%x",
            int(blk.serial),
            int(blk.start),
            int(nop_block.serial),
            int(nop_block.start),
        )
        nop_block.type = ida_hexrays.BLT_1WAY
        nop_block.flags &= ~ida_hexrays.MBL_GOTO
        # SWIG block proxies are not stable across ``insert_block``.  Keep a
        # serial-free live handle through the insertion and reacquire the
        # current C++ target from the gateway-owned identity index.
        target_binding = (
            gateway.resolve_block(target_handle)
            if gateway.active
            else gateway.identity_index.resolve(target_handle)
        )
        current_target = (
            None
            if target_binding is None
            else mba.get_mblock(int(target_binding.serial))
        )
        if current_target is None:
            return None
        target_serial = int(current_target.serial)
        if all(value is not None for value in state_fields):
            assignment = self._materialize_register_state_write(
                ea=assignment_ea,
                state_register=int(state_register),
                state_size=int(state_size),
                state_value=int(state_value),
            )
            nop_block.insert_into_block(assignment, nop_block.tail)
        insert_goto_instruction(
            nop_block, target_serial, nop_previous_instruction=False
        )
        nop_block.flags |= ida_hexrays.MBL_GOTO
        nop_block.succset.push_back(target_serial)
        if nop_block.serial not in [int(p) for p in current_target.predset]:
            current_target.predset.push_back(nop_block.serial)
            if current_target.serial != mba.qty - 1:
                current_target.mark_lists_dirty()
        nop_block.mark_lists_dirty()
        return int(nop_block.serial)

    def _apply_normalize_nway_dispatcher_exit(
        self,
        blk: ida_hexrays.mblock_t,
        *,
        dispatcher_entry_serial: int | None,
        keep_target_serial: int | None = None,
    ) -> bool:
        if dispatcher_entry_serial is None:
            return False
        dispatcher = self._resolve_serial(int(dispatcher_entry_serial))
        keep_target = (
            self._resolve_serial(int(keep_target_serial))
            if keep_target_serial is not None
            else None
        )
        if dispatcher is None:
            return False
        if keep_target is not None and keep_target not in [int(s) for s in blk.succset]:
            logger.warning(
                "normalize_nway_dispatcher_exit: keep target %d is not a successor of block %d",
                keep_target,
                blk.serial,
            )
            return False
        return bool(
            downgrade_nway_null_tail_to_1way(blk, int(dispatcher), verify=False)
        )

    def _apply_bypass_dispatcher_trampoline(
        self,
        blk: ida_hexrays.mblock_t,
        *,
        trampoline_serial: int | None,
        target_serial: int | None,
    ) -> bool:
        if trampoline_serial is None or target_serial is None:
            return False
        trampoline = self._resolve_serial(int(trampoline_serial))
        target = self._resolve_serial(int(target_serial))
        if trampoline is None or target is None:
            return False
        succs = [int(s) for s in blk.succset]
        if int(trampoline) not in succs:
            logger.warning(
                "bypass_dispatcher_trampoline: block %d does not target trampoline %d; succs=%s",
                blk.serial,
                trampoline,
                succs,
            )
            return False
        tail = getattr(blk, "tail", None)
        if tail is not None and int(getattr(tail, "opcode", -1)) == int(
            ida_hexrays.m_jtbl
        ):
            return retarget_jtbl_block_cases(blk, {int(trampoline): int(target)}) > 0
        if blk.nsucc() == 1:
            return change_1way_block_successor(blk, int(target), verify=False)
        if blk.nsucc() == 2:
            return self._apply_target_change(
                blk,
                int(target),
                old_target=int(trampoline),
            )
        logger.warning(
            "bypass_dispatcher_trampoline: unsupported nsucc=%d for block %d",
            blk.nsucc(),
            blk.serial,
        )
        return False

    def _apply_canonicalize_jtbl_case_overlap(
        self,
        blk: ida_hexrays.mblock_t,
        *,
        retarget_map: tuple[tuple[int, int], ...],
        deduplicate: bool = False,
    ) -> bool:
        normalized_map = {
            int(old): int(new) for old, new in retarget_map if int(old) != int(new)
        }
        changed = 0
        if normalized_map:
            changed += retarget_jtbl_block_cases(blk, normalized_map)
        if deduplicate:
            changed += coalesce_jtbl_cases(blk)
        return changed > 0

    def _apply_phase_cycle_lowering(
        self,
        *,
        header_entries: tuple[int, ...],
        header_target: int | None,
        body_entries: tuple[int, ...],
        body_target: int | None,
        next_phase_entries: tuple[int, ...],
        next_phase_target: int | None,
        terminal_entries: tuple[int, ...] = (),
        terminal_target: int | None = None,
    ) -> bool:
        groups = (
            (header_entries, header_target, "header"),
            (body_entries, body_target, "body"),
            (next_phase_entries, next_phase_target, "next_phase"),
            (terminal_entries, terminal_target, "terminal"),
        )
        changed = 0
        for entries, target, role in groups:
            if not entries:
                continue
            if target is None:
                logger.warning("phase_cycle_lowering: %s entries lack a target", role)
                return False
            resolved_target = self._resolve_serial(int(target))
            if resolved_target is None or not _is_live_block_serial(
                self.mba, resolved_target
            ):
                logger.warning(
                    "phase_cycle_lowering: %s target %s is not live",
                    role,
                    target,
                )
                return False
            for entry in entries:
                resolved_entry = self._resolve_serial(int(entry))
                if resolved_entry is None:
                    return False
                phase_blk = self.mba.get_mblock(int(resolved_entry))
                if phase_blk is None:
                    logger.warning(
                        "phase_cycle_lowering: %s entry block %d not found",
                        role,
                        resolved_entry,
                    )
                    return False
                if phase_blk.nsucc() != 1:
                    logger.warning(
                        "phase_cycle_lowering: %s entry block %d is not 1-way (nsucc=%d)",
                        role,
                        resolved_entry,
                        phase_blk.nsucc(),
                    )
                    return False
                if int(phase_blk.succset[0]) == int(resolved_target):
                    continue
                if not change_1way_block_successor(
                    phase_blk,
                    int(resolved_target),
                    verify=False,
                ):
                    return False
                changed += 1
        return changed > 0

    def _apply_create_and_redirect(
        self,
        source_blk: ida_hexrays.mblock_t,
        final_target: int,
        instructions_to_copy: list | tuple | None,
        is_0_way: bool,
        expected_serial: int | None,
        old_target_serial: int | None = None,
    ) -> bool:
        """
        Create a standalone intermediate block and redirect source through it.

        Creates: source_blk -> new_block -> final_target

        Uses :func:`create_standalone_block` instead of :func:`create_block`
        to avoid corrupting ``ref_block``'s CFG edges (INTERR 50856/50858).

        Supports both 1-way and 2-way source blocks. For 2-way sources,
        ``old_target_serial`` must be provided and must equal the conditional
        (taken) arm of the m_jcnd tail (i.e., ``source_blk.tail.d.b``).
        Redirecting the fallthrough arm is not supported.
        """
        logger.info(
            "create_and_redirect: begin src=blk[%d] final=blk[%s] "
            "expected=blk[%s] old_target=blk[%s] qty=%d",
            int(source_blk.serial),
            str(final_target),
            str(expected_serial),
            str(old_target_serial),
            int(getattr(self.mba, "qty", 0) or 0),
        )
        if instructions_to_copy is None:
            instructions_to_copy = []
        try:
            instructions_to_copy = _prepare_block_creation_instructions(
                self.mba,
                instructions_to_copy,
            )
        except Exception as exc:
            logger.error(
                "create_and_redirect: failed preparing %d instruction(s) "
                "for blk[%d]: %s",
                len(instructions_to_copy),
                int(source_blk.serial),
                exc,
            )
            return False
        logger.info(
            "create_and_redirect: prepared %d instruction(s) for blk[%d]",
            len(instructions_to_copy),
            int(source_blk.serial),
        )

        if source_blk.serial == 0:
            logger.warning(
                "create_and_redirect requires non-entry source block; block %d is entry",
                source_blk.serial,
            )
            return False

        nsucc = int(source_blk.nsucc())
        logger.info(
            "create_and_redirect: source blk[%d] nsucc=%d succs=%s",
            int(source_blk.serial),
            nsucc,
            [int(source_blk.succ(idx)) for idx in range(nsucc)],
        )
        if nsucc not in (1, 2):
            logger.warning(
                "create_and_redirect: unsupported nsucc=%d for blk[%d]",
                nsucc,
                source_blk.serial,
            )
            return False

        # Pre-validate 2-way path BEFORE creating the new block to avoid
        # leaving an orphan when the final redirect cannot succeed.
        if nsucc == 2:
            if old_target_serial is None:
                logger.warning(
                    "create_and_redirect: 2-way source blk[%d] requires "
                    "old_target_serial to disambiguate arm",
                    source_blk.serial,
                )
                return False
            tail = source_blk.tail
            if tail is None or not ida_hexrays.is_mcode_jcond(int(tail.opcode)):
                tail_op = int(getattr(tail, "opcode", -1)) if tail is not None else -1
                logger.warning(
                    "create_and_redirect: 2-way source blk[%d] tail is not a "
                    "conditional jump (opcode=%d)",
                    source_blk.serial,
                    tail_op,
                )
                return False
            # change_2way_block_conditional_successor only rewrites the
            # conditional (taken) arm, which lives in tail.d.b. If the
            # caller wants to retarget the fallthrough arm, we cannot do
            # that via this helper without violating physical adjacency.
            try:
                cond_target = int(tail.d.b)
            except Exception:
                logger.warning(
                    "create_and_redirect: 2-way source blk[%d] m_jcnd tail "
                    "has no readable target operand",
                    source_blk.serial,
                )
                return False
            logger.info(
                "create_and_redirect: blk[%d] conditional target=blk[%d]",
                int(source_blk.serial),
                cond_target,
            )
            if cond_target != int(old_target_serial):
                logger.warning(
                    "create_and_redirect: 2-way source blk[%d] conditional "
                    "arm targets blk[%d], expected old_target=%d (likely "
                    "fallthrough arm; refusing to create orphan)",
                    source_blk.serial,
                    cond_target,
                    int(old_target_serial),
                )
                return False

        mba = self.mba

        # Find reference block for copy_block template (tail block, avoiding XTRN/STOP)
        tail_serial = mba.qty - 1
        ref_block = mba.get_mblock(tail_serial)
        while ref_block.type in (ida_hexrays.BLT_XTRN, ida_hexrays.BLT_STOP):
            tail_serial -= 1
            ref_block = mba.get_mblock(tail_serial)
        logger.info(
            "create_and_redirect: ref_block=blk[%d] old_stop=blk[%d] "
            "initial_effective_final=blk[%d]",
            int(ref_block.serial),
            int(mba.qty - 1),
            int(final_target),
        )

        old_stop_serial = mba.qty - 1
        effective_final_target = int(final_target)
        future_stop_target = False
        if not _is_live_block_serial(
            mba, effective_final_target
        ) and effective_final_target >= int(old_stop_serial):
            logger.debug(
                "create_and_redirect: resolving future STOP target blk[%d] "
                "to current STOP blk[%d] for sequential insertion",
                effective_final_target,
                int(old_stop_serial),
            )
            effective_final_target = int(old_stop_serial)
            future_stop_target = True
        logger.info(
            "create_and_redirect: effective_final=blk[%d] future_stop=%s qty=%d",
            int(effective_final_target),
            bool(future_stop_target),
            int(getattr(mba, "qty", 0) or 0),
        )

        # Get target block to check if it's 0-way
        target_blk = (
            mba.get_mblock(effective_final_target)
            if _is_live_block_serial(mba, effective_final_target)
            else None
        )
        actual_is_0_way = is_0_way or (
            target_blk and target_blk.type == ida_hexrays.BLT_0WAY
        )
        logger.info(
            "create_and_redirect: target_live=%s target_type=%s actual_is_0_way=%s",
            target_blk is not None,
            str(int(target_blk.type)) if target_blk is not None else "None",
            bool(actual_is_0_way),
        )

        try:
            old_stop_pred_serials = [
                serial
                for serial in range(mba.qty)
                if (blk := mba.get_mblock(serial)) is not None
                and blk.nsucc() == 1
                and blk.succ(0) == old_stop_serial
            ]
            final_target_was_stop = future_stop_target or (
                not actual_is_0_way
                and _is_live_block_serial(mba, effective_final_target)
                and int(effective_final_target) == int(old_stop_serial)
            )
            # Create a standalone block -- ref_block's CFG edges are NOT modified.
            logger.info(
                "create_and_redirect: create_standalone src=blk[%d] "
                "target=blk[%s] planned_expected=blk[%s]",
                int(source_blk.serial),
                str(None if actual_is_0_way else effective_final_target),
                str(expected_serial),
            )
            if expected_serial is not None:
                self._begin_patch_block_creation(expected_serial)
            new_block = create_standalone_block(
                ref_block,
                instructions_to_copy,
                target_serial=None if actual_is_0_way else effective_final_target,
                is_0_way=actual_is_0_way,
                verify=False,
            )
            logger.info(
                "create_and_redirect: created blk[%d] qty=%d",
                int(new_block.serial),
                int(getattr(mba, "qty", 0) or 0),
            )
            if expected_serial is not None:
                self._bind_patch_block_creation(expected_serial, new_block.serial)
            if expected_serial is not None and new_block.serial != expected_serial:
                logger.info(
                    "create_and_redirect: drift expected blk[%d] -> realized blk[%d] "
                    "recorded in mutation gateway",
                    expected_serial,
                    new_block.serial,
                )
            new_stop_serial = mba.qty - 1
            new_block_nsucc = getattr(new_block, "nsucc", None)
            new_block_succ = getattr(new_block, "succ", None)
            expected_successor = (
                int(new_stop_serial)
                if final_target_was_stop and not actual_is_0_way
                else int(effective_final_target)
            )
            if (
                final_target_was_stop
                and callable(new_block_nsucc)
                and callable(new_block_succ)
                and new_block_nsucc() == 1
                and int(new_block_succ(0)) == int(new_block.serial)
            ):
                logger.debug(
                    "create_and_redirect: retargeting blk[%d] self-loop to moved STOP blk[%d]",
                    new_block.serial,
                    new_stop_serial,
                )
                if not change_1way_block_successor(
                    new_block, new_stop_serial, verify=False
                ):
                    logger.warning(
                        "create_and_redirect: failed to retarget blk[%d] to moved STOP blk[%d]",
                        new_block.serial,
                        new_stop_serial,
                    )
                    return False
            for pred_serial in old_stop_pred_serials:
                pred_blk = mba.get_mblock(pred_serial)
                if pred_blk is None or pred_blk.serial == new_block.serial:
                    continue
                if pred_blk.nsucc() != 1 or pred_blk.succ(0) != new_block.serial:
                    continue
                if not change_1way_block_successor(
                    pred_blk, new_stop_serial, verify=False
                ):
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

            # Redirect source block to the new block. Dispatch on the
            # current source topology: 1-way uses change_1way; 2-way (with
            # validated m_jcnd conditional arm) uses change_2way.
            if nsucc == 1:
                redirect_ok = change_1way_block_successor(
                    source_blk, new_block.serial, verify=False
                )
            else:
                redirect_ok = change_2way_block_conditional_successor(
                    source_blk,
                    new_block.serial,
                    verify=False,
                    old_target=int(old_target_serial)
                    if old_target_serial is not None
                    else None,
                )
            if not redirect_ok:
                logger.warning(
                    "Failed to redirect block %d (nsucc=%d) to new block %d",
                    source_blk.serial,
                    nsucc,
                    new_block.serial,
                )
                # Best-effort cleanup for the partially-created orphan block.
                try:
                    mba_deep_cleaning(self.mba, call_mba_combine_block=False)
                except Exception:
                    pass
                return False

            logger.debug(
                "Created block %d: %d -> %d -> %d (source nsucc=%d)",
                new_block.serial,
                source_blk.serial,
                new_block.serial,
                final_target,
                nsucc,
            )
            # ---- INSERT_BLOCK_INVARIANT: planner-claim vs CFG-state ----
            # User-directed instrumentation (uee-b7ze): verify that the
            # newly created block actually matches what we asked for.
            # Re-read the block from mba so the assertion sees the
            # post-redirect state, not the cached new_block reference.
            try:
                check_blk = mba.get_mblock(new_block.serial)
                check_type = (
                    int(getattr(check_blk, "type", -1)) if check_blk is not None else -1
                )
                check_nsucc = int(check_blk.nsucc()) if check_blk is not None else -1
                check_succ0 = (
                    int(check_blk.succ(0))
                    if (check_blk is not None and check_nsucc >= 1)
                    else -1
                )
                check_head_op = (
                    int(check_blk.head.opcode)
                    if (check_blk is not None and check_blk.head is not None)
                    else -1
                )
                check_ninsns = 0
                if check_blk is not None:
                    cur = check_blk.head
                    while cur is not None:
                        check_ninsns += 1
                        cur = cur.next

                planned_n = (
                    len(instructions_to_copy) if instructions_to_copy is not None else 0
                )
                # Allow trailing m_goto + leading m_nop in the count.
                expected_n_min = planned_n
                expected_n_max = planned_n + 2

                expected_type = (
                    ida_hexrays.BLT_0WAY if actual_is_0_way else ida_hexrays.BLT_1WAY
                )
                pass_type = check_type == int(expected_type)
                pass_succ = actual_is_0_way or check_succ0 == int(expected_successor)
                pass_ninsns = expected_n_min <= check_ninsns <= expected_n_max
                pass_all = pass_type and pass_succ and pass_ninsns

                logger.info(
                    "INSERT_BLOCK_INVARIANT serial=blk[%d]"
                    " expected_type=%d actual_type=%d"
                    " expected_succ=blk[%d] actual_succ=blk[%d] (nsucc=%d)"
                    " planned_ninsns=%d actual_ninsns=%d (head_op=%d)"
                    " result=%s",
                    new_block.serial,
                    int(expected_type),
                    check_type,
                    int(expected_successor),
                    check_succ0,
                    check_nsucc,
                    planned_n,
                    check_ninsns,
                    check_head_op,
                    "PASS" if pass_all else "FAIL",
                )
            except Exception:
                logger.debug(
                    "INSERT_BLOCK_INVARIANT: post-create check raised",
                    exc_info=True,
                )
            return True

        except Exception as e:
            logger.error(
                "Exception in create_and_redirect for block %d: %s",
                source_blk.serial,
                e,
            )
            return False

    def _apply_create_conditional_redirect(
        self,
        source_blk: ida_hexrays.mblock_t,
        ref_blk_serial: int,
        conditional_target_serial: int,
        fallthrough_target_serial: int,
        instructions_to_copy: list | tuple | None = None,
        *,
        old_target_serial: int | None = None,
        expected_conditional_serial: int | None = None,
        expected_fallthrough_serial: int | None = None,
    ) -> bool:
        """
        Create a conditional 2-way block with two wired successors.

        Uses the proven conditional-clone materialization pattern:
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
            old_target_serial: Optional current source successor expected
                before any cloned block is allocated.

        Returns:
            True on success, False on failure
        """
        mba = self.mba
        prelude_instructions = _prepare_block_creation_instructions(
            mba,
            instructions_to_copy,
        )

        if source_blk.nsucc() != 1:
            logger.warning(
                "create_conditional_redirect requires 1-way source block; block %d has nsucc=%d",
                source_blk.serial,
                source_blk.nsucc(),
            )
            return False
        if old_target_serial is not None:
            current_target_serial = int(source_blk.succ(0))
            resolved_old_target_serial = self._resolve_serial(old_target_serial)
            if resolved_old_target_serial is None:
                logger.warning(
                    "create_conditional_redirect: unable to resolve old_target=%s for source block %d",
                    old_target_serial,
                    source_blk.serial,
                )
                return False
            if current_target_serial != int(resolved_old_target_serial):
                logger.warning(
                    "create_conditional_redirect: source block %d targets %d, expected old_target=%d; refusing to create cloned blocks",
                    source_blk.serial,
                    current_target_serial,
                    int(resolved_old_target_serial),
                )
                return False

        # Get reference block to duplicate
        ref_blk = mba.get_mblock(ref_blk_serial)
        if ref_blk is None:
            logger.warning(
                "Reference block %d not found for conditional redirect", ref_blk_serial
            )
            return False

        # Verify reference block is conditional
        if ref_blk.tail is None or not ida_hexrays.is_mcode_jcond(ref_blk.tail.opcode):
            logger.warning(
                "Reference block %d is not conditional (opcode=%s)",
                ref_blk_serial,
                ref_blk.tail.opcode if ref_blk.tail else "none",
            )
            return False

        try:
            # Step 1: Duplicate the conditional block
            # This creates a copy with the same instructions including the
            # conditional tail instruction.
            # For conditional blocks, duplicate_block also creates a NOP
            # fallthrough block automatically (nop_blk).
            planned_creations = tuple(
                serial
                for serial in (
                    expected_conditional_serial,
                    expected_fallthrough_serial,
                )
                if serial is not None
            )
            if planned_creations:
                self._begin_patch_block_creation(*planned_creations)
            new_cond_blk, nop_blk = duplicate_block(ref_blk, verify=False)

            if expected_conditional_serial is not None:
                self._bind_patch_block_creation(
                    expected_conditional_serial,
                    new_cond_blk.serial,
                )
            if nop_blk is None:
                logger.warning(
                    "duplicate_block did not create NOP fallthrough for block %d",
                    new_cond_blk.serial,
                )
                return False
            if expected_fallthrough_serial is not None:
                self._bind_patch_block_creation(
                    expected_fallthrough_serial,
                    nop_blk.serial,
                )
            if (
                expected_conditional_serial is not None
                and new_cond_blk.serial != expected_conditional_serial
            ):
                logger.warning(
                    "create_conditional_redirect: created conditional blk[%d], expected blk[%d]; "
                    "continuing with actual serial and recording remap",
                    new_cond_blk.serial,
                    expected_conditional_serial,
                )
            if (
                expected_fallthrough_serial is not None
                and nop_blk.serial != expected_fallthrough_serial
            ):
                logger.warning(
                    "create_conditional_redirect: created fallthrough blk[%d], expected blk[%d]; "
                    "continuing with actual serial and recording remap",
                    nop_blk.serial,
                    expected_fallthrough_serial,
                )
            resolved_conditional_target_serial = self._resolve_serial(
                conditional_target_serial
            )
            resolved_fallthrough_target_serial = self._resolve_serial(
                fallthrough_target_serial
            )
            if (
                resolved_conditional_target_serial is None
                or resolved_fallthrough_target_serial is None
            ):
                logger.warning(
                    "create_conditional_redirect: unable to resolve targets jcc=%s fallthrough=%s",
                    conditional_target_serial,
                    fallthrough_target_serial,
                )
                return False

            logger.debug(
                "Duplicated conditional block %d -> %d (with NOP fallthrough %d)",
                ref_blk_serial,
                new_cond_blk.serial,
                nop_blk.serial,
            )
            _trace_conditional_redirect_step(
                "after_duplicate",
                mba,
                blocks=(
                    source_blk,
                    ref_blk,
                    new_cond_blk,
                    nop_blk,
                    mba.get_mblock(resolved_conditional_target_serial),
                    mba.get_mblock(resolved_fallthrough_target_serial),
                ),
            )

            if prelude_instructions:
                for insn in reversed(prelude_instructions):
                    cloned_insn = ida_hexrays.minsn_t(insn)
                    cloned_insn.setaddr(mba.entry_ea)
                    new_cond_blk.insert_into_block(cloned_insn, new_cond_blk.head)
                new_cond_blk.mark_lists_dirty()
                _trace_conditional_redirect_step(
                    "after_prelude_insert",
                    mba,
                    blocks=(
                        source_blk,
                        ref_blk,
                        new_cond_blk,
                        nop_blk,
                        mba.get_mblock(resolved_conditional_target_serial),
                        mba.get_mblock(resolved_fallthrough_target_serial),
                    ),
                )

            # Step 2: Wire the conditional target (jcc taken branch)
            # Change the conditional jump's target operand to point to the
            # desired conditional_target_serial
            if not change_2way_block_conditional_successor(
                new_cond_blk, resolved_conditional_target_serial, verify=False
            ):
                logger.warning(
                    "Failed to wire conditional target %d -> %d",
                    new_cond_blk.serial,
                    resolved_conditional_target_serial,
                )
                return False

            logger.debug(
                "Wired conditional target: %d -> %d (jcc taken)",
                new_cond_blk.serial,
                resolved_conditional_target_serial,
            )
            _trace_conditional_redirect_step(
                "after_change_2way",
                mba,
                blocks=(
                    source_blk,
                    ref_blk,
                    new_cond_blk,
                    nop_blk,
                    mba.get_mblock(resolved_conditional_target_serial),
                    mba.get_mblock(resolved_fallthrough_target_serial),
                ),
            )

            # Step 3: Wire the NOP-goto block to the fallthrough target
            # The NOP block was already created by duplicate_block and is
            # adjacent to new_cond_blk (satisfies BLT_2WAY fallthrough requirement).
            # Now we just redirect its goto to the actual fallthrough_target_serial.
            if not change_1way_block_successor(
                nop_blk,
                resolved_fallthrough_target_serial,
                verify=False,
            ):
                logger.warning(
                    "Failed to wire NOP fallthrough %d -> %d",
                    nop_blk.serial,
                    resolved_fallthrough_target_serial,
                )
                return False

            logger.debug(
                "Wired NOP fallthrough: %d -> %d",
                nop_blk.serial,
                resolved_fallthrough_target_serial,
            )
            _trace_conditional_redirect_step(
                "after_helper_rewire",
                mba,
                blocks=(
                    source_blk,
                    ref_blk,
                    new_cond_blk,
                    nop_blk,
                    mba.get_mblock(resolved_conditional_target_serial),
                    mba.get_mblock(resolved_fallthrough_target_serial),
                ),
            )

            # Step 4: Redirect source block to the new conditional block
            if not change_1way_block_successor(
                source_blk, new_cond_blk.serial, verify=False
            ):
                logger.warning(
                    "Failed to redirect source %d -> new conditional %d",
                    source_blk.serial,
                    new_cond_blk.serial,
                )
                try:
                    mba_deep_cleaning(self.mba, call_mba_combine_block=False)
                except Exception:
                    pass
                return False

            logger.debug(
                "Created conditional redirect: %d -> %d (cond) -> jcc:%d / ft:%d (via NOP %d)",
                source_blk.serial,
                new_cond_blk.serial,
                resolved_conditional_target_serial,
                resolved_fallthrough_target_serial,
                nop_blk.serial,
            )
            _trace_conditional_redirect_step(
                "after_source_redirect",
                mba,
                blocks=(
                    source_blk,
                    ref_blk,
                    new_cond_blk,
                    nop_blk,
                    mba.get_mblock(resolved_conditional_target_serial),
                    mba.get_mblock(resolved_fallthrough_target_serial),
                ),
            )

            return True

        except Exception as e:
            logger.error(
                "Exception in create_conditional_redirect for block %d: %s",
                source_blk.serial,
                e,
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
        conditional_target: int | None = None,
        fallthrough_target: int | None = None,
        expected_serial: int | None = None,
        expected_secondary_serial: int | None = None,
        original_redirect_target: int | None = None,
    ) -> bool:
        """Duplicate ``source_blk`` and redirect ``pred_serial`` to the clone.

        When *original_redirect_target* is not ``None``, the original block's
        1-way successor is also redirected to that serial after the clone is
        wired up — making the whole operation atomic.
        """
        if not self._check_duplicate_block_preconditions(
            source_block_serial=source_blk.serial,
            pred_serial=pred_serial,
            target_serial=target_serial,
            conditional_target=conditional_target,
            fallthrough_target=fallthrough_target,
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
                effective_conditional_target = (
                    conditional_target
                    if conditional_target is not None
                    else source_blk.tail.d.b
                )
                effective_fallthrough_target = (
                    fallthrough_target
                    if fallthrough_target is not None
                    else next(
                        (
                            source_blk.succ(i)
                            for i in range(source_blk.nsucc())
                            if source_blk.succ(i) != source_blk.tail.d.b
                        ),
                        None,
                    )
                )
                if effective_fallthrough_target is None:
                    logger.warning(
                        "duplicate_block: src blk[%d] missing fallthrough successor",
                        source_blk.serial,
                    )
                    return False
                if effective_conditional_target == effective_fallthrough_target:
                    logger.warning(
                        "duplicate_block: src blk[%d] has identical conditional/fallthrough target %d",
                        source_blk.serial,
                        effective_conditional_target,
                    )
                    return False
                planned_creations = tuple(
                    serial
                    for serial in (expected_serial, expected_secondary_serial)
                    if serial is not None
                )
                if planned_creations:
                    self._begin_patch_block_creation(*planned_creations)
                duplicated_blk = copy_block_keep(self.mba, source_blk, self.mba.qty - 1)
                if expected_serial is not None:
                    self._bind_patch_block_creation(
                        expected_serial,
                        duplicated_blk.serial,
                    )
                prev_pred_serials = [x for x in duplicated_blk.predset]
                for prev_serial in prev_pred_serials:
                    duplicated_blk.predset._del(prev_serial)

                prev_blk = duplicated_blk.prevb
                if prev_blk is not None and prev_blk.serial != source_blk.serial:
                    tail = prev_blk.tail
                    has_explicit_target = tail is not None and (
                        tail.opcode == ida_hexrays.m_goto
                        or ida_hexrays.is_mcode_jcond(tail.opcode)
                        or tail.opcode == ida_hexrays.m_ijmp
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
                                prev_blk.succset[i]
                                for i in range(prev_blk.succset.size())
                            ]:
                                prev_blk.succset.push_back(original_target)
                            prev_blk.type = ida_hexrays.BLT_1WAY
                            prev_blk.flags |= ida_hexrays.MBL_GOTO
                            prev_blk.mark_lists_dirty()

                duplicated_default = create_standalone_block(
                    source_blk,
                    [],
                    target_serial=effective_fallthrough_target,
                    is_0_way=False,
                    verify=False,
                )
                if expected_secondary_serial is not None:
                    self._bind_patch_block_creation(
                        expected_secondary_serial,
                        duplicated_default.serial,
                    )
                duplicated_blk.flags &= ~ida_hexrays.MBL_GOTO
                if not _rewire_edge(
                    duplicated_blk,
                    [x for x in duplicated_blk.succset],
                    [duplicated_default.serial, effective_conditional_target],
                    new_block_type=ida_hexrays.BLT_2WAY,
                    verify=False,
                ):
                    return False
                duplicated_blk.tail.d = ida_hexrays.mop_t()
                duplicated_blk.tail.d.make_blkref(effective_conditional_target)
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

                if expected_serial is not None:
                    self._begin_patch_block_creation(expected_serial)
                duplicated_blk = create_standalone_block(
                    source_blk,
                    instructions_to_copy,
                    target_serial=final_target,
                    is_0_way=final_target is None,
                    verify=False,
                )
                if expected_serial is not None:
                    self._bind_patch_block_creation(
                        expected_serial,
                        duplicated_blk.serial,
                    )
                duplicated_default = None
            new_stop_serial = self.mba.qty - 1
            transient_stop_targets = {duplicated_blk.serial}
            if duplicated_default is not None:
                transient_stop_targets.add(duplicated_default.serial)
            for stop_pred_serial in old_stop_pred_serials:
                stop_pred_blk = self.mba.get_mblock(stop_pred_serial)
                if (
                    stop_pred_blk is None
                    or stop_pred_blk.serial == duplicated_blk.serial
                ):
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
                logger.info(
                    "duplicate_block: created clone blk[%d], expected blk[%d] "
                    "(serial drift from prior mod); recording remap",
                    duplicated_blk.serial,
                    expected_serial,
                )
            if expected_secondary_serial is not None:
                if duplicated_default is None:
                    logger.warning(
                        "duplicate_block: missing duplicated fallthrough blk for blk[%d], expected blk[%d]",
                        source_blk.serial,
                        expected_secondary_serial,
                    )
                    return False
                if duplicated_default.serial != expected_secondary_serial:
                    logger.info(
                        "duplicate_block: created fallthrough blk[%d], expected blk[%d] "
                        "(serial drift from prior mod); recording remap",
                        duplicated_default.serial,
                        expected_secondary_serial,
                    )

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

            # Optionally redirect the original block's successor (atomic
            # Typed clone/split: clone + redirect clone + redirect original).
            if original_redirect_target is not None:
                if source_blk.nsucc() != 1:
                    logger.warning(
                        "duplicate_block: cannot redirect original blk[%d] "
                        "(nsucc=%d, expected 1)",
                        source_blk.serial,
                        source_blk.nsucc(),
                    )
                    return False
                if not change_1way_block_successor(
                    source_blk,
                    original_redirect_target,
                    verify=False,
                ):
                    logger.warning(
                        "duplicate_block: failed to redirect original blk[%d] -> %d",
                        source_blk.serial,
                        original_redirect_target,
                    )
                    return False
                logger.debug(
                    "duplicate_block: also redirected original blk[%d] -> %d",
                    source_blk.serial,
                    original_redirect_target,
                )

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

    def _apply_duplicate_replay_and_redirect(
        self,
        *,
        source_blk: ida_hexrays.mblock_t,
        dispatcher_entry_serial: int | None,
        replay_entries: tuple,
    ) -> bool:
        """Apply duplicate-group replay as one source-owned operation.

        Direct replay ``InsertBlock`` cannot model this shape: the shared source
        has multiple predecessors that need distinct targets, and replaying from
        the predecessor edge would skip the shared source body.  This operation
        creates replay blocks first, duplicates the source for all but the kept
        predecessor, then redirects the original source to the first replay.
        """
        if dispatcher_entry_serial is None or len(replay_entries) < 2:
            return False
        if source_blk.nsucc() != 1 or int(source_blk.succ(0)) != int(
            dispatcher_entry_serial
        ):
            logger.warning(
                "duplicate_replay: source blk[%d] is not one-way to dispatcher %s",
                source_blk.serial,
                dispatcher_entry_serial,
            )
            return False

        seen_preds: set[int] = set()
        normalized_entries: list[tuple[int, int, int, int | None, tuple]] = []
        for row in replay_entries:
            if not isinstance(row, tuple) or len(row) != 5:
                logger.warning("duplicate_replay: malformed replay row %r", row)
                return False
            pred_serial, target_serial, replay_serial, clone_serial, instructions = row
            if pred_serial in seen_preds:
                logger.warning(
                    "duplicate_replay: duplicate predecessor %s", pred_serial
                )
                return False
            seen_preds.add(int(pred_serial))
            pred_blk = self.mba.get_mblock(int(pred_serial))
            target_blk = self.mba.get_mblock(int(target_serial))
            if pred_blk is None or target_blk is None:
                logger.warning(
                    "duplicate_replay: missing pred/target pred=%s target=%s",
                    pred_serial,
                    target_serial,
                )
                return False
            if pred_blk.nsucc() != 1 or int(pred_blk.succ(0)) != int(source_blk.serial):
                logger.warning(
                    "duplicate_replay: pred blk[%d] is not one-way to source blk[%d]",
                    int(pred_serial),
                    source_blk.serial,
                )
                return False
            prepared_instructions = tuple(
                _prepare_block_creation_instructions(self.mba, instructions)
            )
            if not prepared_instructions:
                logger.warning(
                    "duplicate_replay: empty replay body for pred blk[%d]",
                    int(pred_serial),
                )
                return False
            normalized_entries.append(
                (
                    int(pred_serial),
                    int(target_serial),
                    int(replay_serial),
                    None if clone_serial is None else int(clone_serial),
                    prepared_instructions,
                )
            )

        if seen_preds != {int(pred) for pred in list(source_blk.predset)}:
            logger.warning(
                "duplicate_replay: replay rows do not cover source preds rows=%s preds=%s",
                sorted(seen_preds),
                sorted(int(pred) for pred in list(source_blk.predset)),
            )
            return False

        created_replays: dict[int, int] = {}

        def _create_replay_block(
            *,
            pred_serial: int,
            target_serial: int,
            expected_serial: int,
            instructions: tuple,
        ) -> int | None:
            old_stop_serial = self.mba.qty - 1
            old_stop_pred_serials = [
                serial
                for serial in range(self.mba.qty)
                if (blk := self.mba.get_mblock(serial)) is not None
                and blk.nsucc() == 1
                and blk.succ(0) == old_stop_serial
            ]
            self._begin_patch_block_creation(expected_serial)
            replay_blk = create_standalone_block(
                source_blk,
                instructions,
                target_serial=target_serial,
                is_0_way=False,
                verify=False,
            )
            self._bind_patch_block_creation(expected_serial, replay_blk.serial)
            if expected_serial is not None and replay_blk.serial != expected_serial:
                logger.info(
                    "duplicate_replay: replay blk drift pred=%d expected=%d actual=%d",
                    pred_serial,
                    expected_serial,
                    replay_blk.serial,
                )
            new_stop_serial = self.mba.qty - 1
            for stop_pred_serial in old_stop_pred_serials:
                stop_pred_blk = self.mba.get_mblock(stop_pred_serial)
                if stop_pred_blk is None or stop_pred_blk.serial == replay_blk.serial:
                    continue
                if (
                    stop_pred_blk.nsucc() != 1
                    or stop_pred_blk.succ(0) != replay_blk.serial
                ):
                    continue
                if not change_1way_block_successor(
                    stop_pred_blk,
                    new_stop_serial,
                    verify=False,
                ):
                    logger.warning(
                        "duplicate_replay: failed to relocate stop predecessor blk[%d]",
                        stop_pred_serial,
                    )
                    return None
            safe_ea = self.mba.entry_ea
            cur = replay_blk.head
            while cur is not None:
                cur.ea = safe_ea
                cur = cur.next
            created_replays[pred_serial] = int(replay_blk.serial)
            return int(replay_blk.serial)

        try:
            for (
                pred_serial,
                target_serial,
                replay_serial,
                _clone_serial,
                instructions,
            ) in normalized_entries:
                replay_blk_serial = _create_replay_block(
                    pred_serial=pred_serial,
                    target_serial=target_serial,
                    expected_serial=replay_serial,
                    instructions=instructions,
                )
                if replay_blk_serial is None:
                    return False

            for (
                pred_serial,
                _target_serial,
                _replay_serial,
                clone_serial,
                _instructions,
            ) in normalized_entries[1:]:
                if clone_serial is None:
                    logger.warning(
                        "duplicate_replay: missing clone serial for pred blk[%d]",
                        pred_serial,
                    )
                    return False
                replay_blk_serial = created_replays[pred_serial]
                if not self._apply_duplicate_block_and_redirect(
                    source_blk=source_blk,
                    pred_serial=pred_serial,
                    target_serial=replay_blk_serial,
                    expected_serial=clone_serial,
                ):
                    return False

            keep_pred = normalized_entries[0][0]
            keep_replay = created_replays[keep_pred]
            if source_blk.nsucc() != 1 or int(source_blk.succ(0)) != int(
                dispatcher_entry_serial
            ):
                logger.warning(
                    "duplicate_replay: source blk[%d] no longer targets dispatcher %s",
                    source_blk.serial,
                    dispatcher_entry_serial,
                )
                return False
            remaining_preds = {int(pred) for pred in list(source_blk.predset)}
            if remaining_preds != {keep_pred}:
                logger.warning(
                    "duplicate_replay: source blk[%d] remaining preds %s, expected [%d]",
                    source_blk.serial,
                    sorted(remaining_preds),
                    keep_pred,
                )
                return False
            if not change_1way_block_successor(source_blk, keep_replay, verify=False):
                logger.warning(
                    "duplicate_replay: failed to redirect original blk[%d] -> replay blk[%d]",
                    source_blk.serial,
                    keep_replay,
                )
                return False
            self.mba.mark_chains_dirty()
            logger.debug(
                "duplicate_replay: source=%d rows=%d applied",
                source_blk.serial,
                len(normalized_entries),
            )
            return True
        except Exception as exc:
            logger.error(
                "Exception in duplicate_replay for src=%d: %s",
                source_blk.serial,
                exc,
            )
            import traceback

            logger.error("Traceback: %s", traceback.format_exc())
            return False

    def _apply_clone_conditional_as_goto(
        self,
        *,
        source_blk: ida_hexrays.mblock_t,
        pred_serial: int | None,
        goto_target_serial: int | None,
        expected_serial: int | None = None,
    ) -> bool:
        """Clone a conditional block as a goto and redirect one predecessor.

        This is the planned form of the predecessor-repair rewrite for the
        simple one-way predecessor case.
        """
        if not self._check_clone_conditional_as_goto_preconditions(
            source_block_serial=source_blk.serial,
            pred_serial=pred_serial,
            goto_target_serial=goto_target_serial,
        ):
            return False

        if pred_serial is None or goto_target_serial is None:
            return False

        pred_blk = self.mba.get_mblock(pred_serial)
        if pred_blk is None:
            logger.warning(
                "clone_conditional_as_goto: predecessor blk[%d] missing at apply-time",
                pred_serial,
            )
            return False

        try:
            if expected_serial is not None:
                self._begin_patch_block_creation(expected_serial)
            cloned_blk = copy_block_keep(self.mba, source_blk, self.mba.qty - 1)
            if cloned_blk is None:
                logger.warning(
                    "clone_conditional_as_goto: failed to clone blk[%d]",
                    source_blk.serial,
                )
                return False
            cloned_blk = self.mba.get_mblock(cloned_blk.serial) or cloned_blk
            if expected_serial is not None:
                self._bind_patch_block_creation(expected_serial, cloned_blk.serial)

            for prev_serial in list(cloned_blk.predset):
                cloned_blk.predset._del(prev_serial)
            cloned_blk.mark_lists_dirty()
            self.mba.mark_chains_dirty()

            if expected_serial is not None and cloned_blk.serial != expected_serial:
                logger.info(
                    "clone_conditional_as_goto: created clone blk[%d], expected blk[%d] "
                    "(serial drift from prior mod); recording remap",
                    cloned_blk.serial,
                    expected_serial,
                )

            target_serial = self._resolve_serial(goto_target_serial)
            if self.mba.get_mblock(target_serial) is None:
                logger.warning(
                    "clone_conditional_as_goto: target blk[%d] missing after clone",
                    target_serial,
                )
                mba_deep_cleaning(self.mba, call_mba_combine_block=False)
                return False

            if not make_2way_block_goto(cloned_blk, int(target_serial), verify=False):
                logger.warning(
                    "clone_conditional_as_goto: failed to convert clone blk[%d] "
                    "to goto blk[%d]",
                    cloned_blk.serial,
                    target_serial,
                )
                mba_deep_cleaning(self.mba, call_mba_combine_block=False)
                return False

            if not change_1way_block_successor(
                pred_blk,
                cloned_blk.serial,
                verify=False,
            ):
                logger.warning(
                    "clone_conditional_as_goto: failed to redirect pred blk[%d] "
                    "to clone blk[%d]",
                    pred_blk.serial,
                    cloned_blk.serial,
                )
                mba_deep_cleaning(self.mba, call_mba_combine_block=False)
                return False

            self.mba.mark_chains_dirty()
            logger.debug(
                "clone_conditional_as_goto: pred=%d -> clone=%d -> target=%d "
                "(source=%d preserved)",
                pred_blk.serial,
                cloned_blk.serial,
                target_serial,
                source_blk.serial,
            )
            return True
        except Exception as exc:
            logger.error(
                "Exception in clone_conditional_as_goto for src=%d pred=%s target=%s: %s",
                source_blk.serial,
                pred_serial,
                goto_target_serial,
                exc,
            )
            import traceback

            logger.error("Traceback: %s", traceback.format_exc())
            return False

    def _apply_clone_conditional_as_goto_from_branch_arm(
        self,
        *,
        source_blk: ida_hexrays.mblock_t,
        pred_serial: int | None,
        goto_target_serial: int | None,
        pred_arm: int | None = 1,
        expected_serial: int | None = None,
    ) -> bool:
        """Clone a 2-way conditional block as a goto and rewire one 2-way predecessor's branch arm.

        Sibling of :meth:`_apply_clone_conditional_as_goto` for the
        ``two_way_predecessor_arm_known`` shape.  The mechanical difference
        is the final rewire step: explicit branch arms use
        ``change_2way_block_conditional_successor`` and fallthrough arms use
        the adjacent helper-block fallthrough rewrite.
        """
        if not self._check_clone_conditional_as_goto_preconditions(
            source_block_serial=source_blk.serial,
            pred_serial=pred_serial,
            goto_target_serial=goto_target_serial,
            pred_topology="two_way_branch_arm",
            pred_arm=pred_arm,
        ):
            return False

        if pred_serial is None or goto_target_serial is None:
            return False

        pred_blk = self.mba.get_mblock(pred_serial)
        if pred_blk is None:  # preconditions already cover this; defensive
            return False

        try:
            if expected_serial is not None:
                self._begin_patch_block_creation(expected_serial)
            cloned_blk = copy_block_keep(self.mba, source_blk, self.mba.qty - 1)
            if cloned_blk is None:
                logger.warning(
                    "clone_conditional_as_goto_from_branch_arm: failed to clone blk[%d]",
                    source_blk.serial,
                )
                return False
            cloned_blk = self.mba.get_mblock(cloned_blk.serial) or cloned_blk
            if expected_serial is not None:
                self._bind_patch_block_creation(expected_serial, cloned_blk.serial)

            for prev_serial in list(cloned_blk.predset):
                cloned_blk.predset._del(prev_serial)
            cloned_blk.mark_lists_dirty()
            self.mba.mark_chains_dirty()

            if expected_serial is not None and cloned_blk.serial != expected_serial:
                logger.info(
                    "clone_conditional_as_goto_from_branch_arm: created clone "
                    "blk[%d], expected blk[%d] (serial drift); recording remap",
                    cloned_blk.serial,
                    expected_serial,
                )

            target_serial = self._resolve_serial(goto_target_serial)
            if self.mba.get_mblock(target_serial) is None:
                logger.warning(
                    "clone_conditional_as_goto_from_branch_arm: target blk[%d] "
                    "missing after clone",
                    target_serial,
                )
                mba_deep_cleaning(self.mba, call_mba_combine_block=False)
                return False

            if pred_arm == 1:
                if not make_2way_block_goto(
                    cloned_blk, int(target_serial), verify=False
                ):
                    logger.warning(
                        "clone_conditional_as_goto_from_branch_arm: failed to convert "
                        "clone blk[%d] to goto blk[%d]",
                        cloned_blk.serial,
                        target_serial,
                    )
                    mba_deep_cleaning(self.mba, call_mba_combine_block=False)
                    return False
                rewired = change_2way_block_conditional_successor(
                    pred_blk,
                    cloned_blk.serial,
                    verify=False,
                    old_target=int(source_blk.serial),
                )
            else:
                clone_serial_before_rewire = int(cloned_blk.serial)
                rewired = self._apply_fallthrough_change(
                    pred_blk,
                    clone_serial_before_rewire,
                    old_target=int(source_blk.serial),
                )
                if rewired:
                    cloned_serial = self._resolve_serial(clone_serial_before_rewire)
                    cloned_blk = self.mba.get_mblock(cloned_serial) or cloned_blk
                    target_serial = self._resolve_serial(goto_target_serial)
                    if self.mba.get_mblock(target_serial) is None:
                        logger.warning(
                            "clone_conditional_as_goto_from_branch_arm: target blk[%d] "
                            "missing after fallthrough helper insertion",
                            target_serial,
                        )
                        mba_deep_cleaning(self.mba, call_mba_combine_block=False)
                        return False
                    if not make_2way_block_goto(
                        cloned_blk, int(target_serial), verify=False
                    ):
                        logger.warning(
                            "clone_conditional_as_goto_from_branch_arm: failed to convert "
                            "clone blk[%d] to goto blk[%d] after fallthrough helper insertion",
                            cloned_blk.serial,
                            target_serial,
                        )
                        mba_deep_cleaning(self.mba, call_mba_combine_block=False)
                        return False
            if not rewired:
                logger.warning(
                    "clone_conditional_as_goto_from_branch_arm: failed to rewire "
                    "pred blk[%d] arm=%s to clone blk[%d]",
                    pred_blk.serial,
                    pred_arm,
                    cloned_blk.serial,
                )
                mba_deep_cleaning(self.mba, call_mba_combine_block=False)
                return False

            self.mba.mark_chains_dirty()
            logger.debug(
                "clone_conditional_as_goto_from_branch_arm: pred=%d arm=%s -> "
                "clone=%d -> target=%d (source=%d preserved)",
                pred_blk.serial,
                pred_arm,
                cloned_blk.serial,
                target_serial,
                source_blk.serial,
            )
            return True
        except Exception as exc:
            logger.error(
                "Exception in clone_conditional_as_goto_from_branch_arm for "
                "src=%d pred=%s target=%s: %s",
                source_blk.serial,
                pred_serial,
                goto_target_serial,
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

        # Validate suffix topology. Earlier block-creating edits insert before
        # BLT_STOP, so a planned final suffix serial can become a historical
        # stop handle while the live stop moves to ``mba.qty - 1``.
        final_stop_relocated = False
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
                    current_stop_serial = mba.qty - 1
                    current_stop_blk = mba.get_mblock(current_stop_serial)
                    if current_stop_blk is None or current_stop_blk.nsucc() != 0:
                        logger.warning(
                            "private_terminal_suffix: final suffix blk[%d] is not 0-way "
                            "(nsucc=%d), and current stop blk[%d] is invalid (nsucc=%d)",
                            suffix_serial,
                            suffix_blk.nsucc(),
                            current_stop_serial,
                            (
                                current_stop_blk.nsucc()
                                if current_stop_blk is not None
                                else -1
                            ),
                        )
                        return False
                    final_stop_relocated = True
                    logger.debug(
                        "private_terminal_suffix: final suffix blk[%d] relocated "
                        "to current stop blk[%d]",
                        suffix_serial,
                        current_stop_serial,
                    )

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
            clone_source_serials = (
                tuple(suffix_serials[:-1])
                if final_stop_relocated
                else tuple(suffix_serials)
            )
            if not clone_source_serials:
                logger.warning("private_terminal_suffix: no suffix blocks to clone")
                return False
            # Clone suffix blocks in forward order (each creates a new block)
            for idx, suffix_serial in enumerate(clone_source_serials):
                template_blk = mba.get_mblock(suffix_serial)
                if template_blk is None:
                    return False

                is_last = (
                    idx == len(clone_source_serials) - 1 and not final_stop_relocated
                )

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
                if (
                    stop_pred_blk is None
                    or stop_pred_blk.serial in transient_stop_targets
                ):
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

            if final_stop_relocated:
                last_clone_blk = mba.get_mblock(cloned_serials[-1])
                if last_clone_blk is None:
                    return False
                new_stop_serial = mba.qty - 1
                if not change_1way_block_successor(
                    last_clone_blk,
                    new_stop_serial,
                    verify=False,
                ):
                    logger.warning(
                        "private_terminal_suffix: failed to wire clone blk[%d] "
                        "to relocated stop blk[%d]",
                        cloned_serials[-1],
                        new_stop_serial,
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
        # Earlier additive edits can relocate BLT_STOP. Interior suffix
        # serials must still be stable 1-way blocks; the final serial may be
        # the historical stop, in which case the current live stop is
        # ``mba.qty - 1``.
        for idx, suffix_serial in enumerate(suffix_serials):
            if suffix_serial >= mba.qty:
                logger.warning(
                    "private_terminal_suffix_group: suffix blk[%d] out of range "
                    "(mba.qty=%d)",
                    suffix_serial,
                    mba.qty,
                )
                return False
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
                    current_stop_serial = mba.qty - 1
                    current_stop_blk = mba.get_mblock(current_stop_serial)
                    if current_stop_blk is None or current_stop_blk.nsucc() != 0:
                        logger.warning(
                            "private_terminal_suffix_group: final suffix blk[%d] "
                            "is not 0-way (nsucc=%d), and current stop blk[%d] "
                            "is invalid (nsucc=%d)",
                            suffix_serial,
                            suffix_blk.nsucc(),
                            current_stop_serial,
                            (
                                current_stop_blk.nsucc()
                                if current_stop_blk is not None
                                else -1
                            ),
                        )
                        return False
                    logger.debug(
                        "private_terminal_suffix_group: final suffix blk[%d] "
                        "relocated to current stop blk[%d]",
                        suffix_serial,
                        current_stop_serial,
                    )

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
            logger.debug(
                "PTS_DIAG Phase3: old_stop_pred_serials=%s, BLT_STOP_serial=%d, mba.qty=%d",
                old_stop_pred_serials,
                suffix_serials[-1],
                mba.qty,
            )

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

            logger.debug(
                "PTS_DIAG pre_Phase4: suffix_templates serials=%s, mba.qty=%d",
                [t.serial for t in suffix_templates],
                mba.qty,
            )

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
                    logger.debug(
                        "PTS_DIAG Phase4: anchor[%d]=%d, suffix[%d]=%d, clone_serial=%d, clone.type=%d, "
                        "clone.nsucc=%d, clone.npred=%d, mba.qty=%d, BLT_STOP_now=%d",
                        anchor_idx,
                        anchor_serial,
                        idx,
                        suffix_serial,
                        cloned_blk.serial,
                        cloned_blk.type,
                        cloned_blk.nsucc(),
                        cloned_blk.npred(),
                        mba.qty,
                        mba.qty - 1,
                    )
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
                    logger.debug(
                        "PTS_DIAG Phase4_wire: clone[%d]=%d -> clone[%d]=%d, ok=%s, "
                        "clone_nsucc=%d, clone_succ0=%s",
                        idx,
                        cloned_serials[idx],
                        idx + 1,
                        next_clone_serial,
                        wire_ok,
                        clone_blk.nsucc(),
                        clone_blk.succ(0) if clone_blk.nsucc() > 0 else -1,
                    )
                    if not wire_ok:
                        logger.debug(
                            "PTS_DIAG Phase4_wire FAILED: blk[%d].type=%d, nsucc=%d, npred=%d",
                            cloned_serials[idx],
                            clone_blk.type,
                            clone_blk.nsucc(),
                            clone_blk.npred(),
                        )
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
                logger.debug(
                    "PTS_DIAG Phase4_wire_to_stop: clone[%d]=%d -> BLT_STOP=%d, ok=%s",
                    len(cloned_serials) - 1,
                    last_clone_serial,
                    stop_serial,
                    wire_ok,
                )
                if not wire_ok:
                    return False

                per_anchor_first_clone.append(cloned_serials[0])

                # Validate expected serials (informational only)
                if per_anchor_clone_expected_serials and anchor_idx < len(
                    per_anchor_clone_expected_serials
                ):
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

            logger.debug(
                "PTS_DIAG post_Phase4: all_cloned_serials=%s, per_anchor_first=%s, mba.qty=%d",
                sorted(all_cloned_serials),
                per_anchor_first_clone,
                mba.qty,
            )

            # ---- Phase 5: Redirect ALL anchors to their first clones ----
            for anchor_idx, anchor_blk in enumerate(anchor_blks):
                redirect_ok = change_1way_block_successor(
                    anchor_blk,
                    per_anchor_first_clone[anchor_idx],
                    verify=False,
                )
                logger.debug(
                    "PTS_DIAG Phase5: anchor[%d]=%d -> first_clone=%d, ok=%s, "
                    "anchor_nsucc=%d, anchor_succ0=%s",
                    anchor_idx,
                    anchor_blk.serial,
                    per_anchor_first_clone[anchor_idx],
                    redirect_ok,
                    anchor_blk.nsucc(),
                    anchor_blk.succ(0) if anchor_blk.nsucc() > 0 else -1,
                )
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
            logger.debug(
                "PTS_DIAG Phase6: new_stop_serial=%d, old_stop_pred_serials=%s, all_cloned=%s",
                new_stop_serial,
                old_stop_pred_serials,
                sorted(all_cloned_serials),
            )
            for stop_pred_serial in old_stop_pred_serials:
                stop_pred_blk = mba.get_mblock(stop_pred_serial)
                if stop_pred_blk is None or stop_pred_blk.serial in all_cloned_serials:
                    logger.debug(
                        "PTS_DIAG Phase6: skip pred_serial=%d (None=%s, in_cloned=%s)",
                        stop_pred_serial,
                        stop_pred_blk is None,
                        stop_pred_serial in all_cloned_serials,
                    )
                    continue
                if (
                    stop_pred_blk.nsucc() != 1
                    or stop_pred_blk.succ(0) not in all_cloned_serials
                ):
                    logger.debug(
                        "PTS_DIAG Phase6: skip pred_blk[%d] nsucc=%d, succ0=%s, succ0_in_cloned=%s",
                        stop_pred_blk.serial,
                        stop_pred_blk.nsucc(),
                        stop_pred_blk.succ(0) if stop_pred_blk.nsucc() > 0 else -1,
                        stop_pred_blk.succ(0) in all_cloned_serials
                        if stop_pred_blk.nsucc() > 0
                        else False,
                    )
                    continue
                old_succ = stop_pred_blk.succ(0)
                relocate_ok = change_1way_block_successor(
                    stop_pred_blk,
                    new_stop_serial,
                    verify=False,
                )
                logger.debug(
                    "PTS_DIAG Phase6: pred_blk[%d].succ(0)=%d -> new_stop=%d, ok=%s",
                    stop_pred_blk.serial,
                    old_succ,
                    new_stop_serial,
                    relocate_ok,
                )
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
            logger.info(
                "PTS group applied: %d anchors, %d clones, shared_entry=%d, stop=%d",
                len(anchors),
                len(all_cloned_serials),
                shared_entry_serial,
                mba.qty - 1,
            )
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
        from d810.transforms.graph_modification import (
            ExitPathLoweringKind,
            ExitPathLoweringSite,
        )

        if mba is None:
            return False

        sites: tuple[ExitPathLoweringSite, ...] = mod.sites or ()
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
                # The final suffix serial is the return/STOP block captured
                # during planning. Earlier block-creating modifications can
                # relocate the live BLT_STOP, so validate the current stop
                # instead of requiring this historical serial to remain 0-way.
                current_stop_serial = mba.qty - 1
                current_stop_blk = mba.get_mblock(current_stop_serial)
                if current_stop_blk is None or current_stop_blk.nsucc() != 0:
                    logger.warning(
                        "direct_terminal_lowering_group: current stop blk[%d] "
                        "is not 0-way (nsucc=%d)",
                        current_stop_serial,
                        current_stop_blk.nsucc()
                        if current_stop_blk is not None
                        else -1,
                    )
                    return False
                if int(suffix_serial) != current_stop_serial:
                    logger.debug(
                        "direct_terminal_lowering_group: final suffix blk[%d] "
                        "relocated to current stop blk[%d]",
                        suffix_serial,
                        current_stop_serial,
                    )

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

            def _terminal_return_destination_mop():
                for suffix_serial in interior_suffix_serials:
                    suffix_blk = mba.get_mblock(suffix_serial)
                    if suffix_blk is None:
                        continue
                    cur = suffix_blk.head
                    while cur is not None:
                        if (
                            cur.opcode == ida_hexrays.m_mov
                            and getattr(cur.d, "t", None) == ida_hexrays.mop_r
                        ):
                            return ida_hexrays.mop_t(cur.d)
                        cur = cur.next
                return None

            def _make_return_const_insn(value: int, dst_mop) -> object:
                insn = ida_hexrays.minsn_t(mba.entry_ea)
                insn.opcode = ida_hexrays.m_mov
                size = int(getattr(dst_mop, "size", 0) or 8)
                mask = (1 << (size * 8)) - 1
                insn.l = ida_hexrays.mop_t()
                insn.l.make_number(int(value) & mask, size, mba.entry_ea)
                insn.r = ida_hexrays.mop_t()
                insn.r.erase()
                insn.d = ida_hexrays.mop_t(dst_mop)
                return insn

            def _rewrite_anchor_as_return_const(
                anchor_blk, value: int, dst_mop
            ) -> bool:
                target_insn = None
                tail = anchor_blk.tail
                cur = anchor_blk.head
                while cur is not None:
                    next_insn = cur.next
                    if cur is not tail:
                        if target_insn is None:
                            target_insn = cur
                        else:
                            anchor_blk.make_nop(cur)
                    cur = next_insn
                if target_insn is None:
                    logger.warning(
                        "direct_terminal_lowering_group: RETURN_CONST anchor "
                        "blk[%d] has no carrier instruction to rewrite",
                        anchor_blk.serial,
                    )
                    return False

                replacement = _make_return_const_insn(value, dst_mop)
                anchor_blk.make_nop(target_insn)
                target_insn.opcode = replacement.opcode
                target_insn.ea = mba.entry_ea
                target_insn.l = ida_hexrays.mop_t(replacement.l)
                target_insn.r = ida_hexrays.mop_t(replacement.r)
                target_insn.d = ida_hexrays.mop_t(replacement.d)
                anchor_blk.type = ida_hexrays.BLT_1WAY
                anchor_blk.flags |= ida_hexrays.MBL_GOTO
                anchor_blk.mark_lists_dirty()
                mba.mark_chains_dirty()
                return True

            # ---- Phase 4: Create private blocks per site ----
            per_site_first_clone: list[int] = []

            for site_idx, site in enumerate(sites):
                # Determine materializer serials for this site.
                # For CLONE_MATERIALIZER: use site.materializer_serials
                # For RETURN_CONST: rewrite the anchor to materialize the
                # literal directly and route it to the live STOP. This matches
                # the typed CFG contract, which allocates no clones for this
                # lowering kind.
                # For RETURN_FROM_SLOT/REG (v2 fallback): use interior suffix serials
                if site.kind == ExitPathLoweringKind.RETURN_CONST:
                    if site.const_value is None:
                        logger.warning(
                            "direct_terminal_lowering_group: RETURN_CONST site "
                            "anchor=%d has no const_value",
                            site.anchor_serial,
                        )
                        return False
                    dst_mop = _terminal_return_destination_mop()
                    if dst_mop is None:
                        logger.warning(
                            "direct_terminal_lowering_group: RETURN_CONST site "
                            "anchor=%d cannot find terminal return destination",
                            site.anchor_serial,
                        )
                        return False
                    if not _rewrite_anchor_as_return_const(
                        anchor_blks[site_idx],
                        int(site.const_value),
                        dst_mop,
                    ):
                        return False
                    try:
                        from d810.hexrays.mutation.terminal_return_literals import (
                            remember_terminal_zero_guard_literal_return_value,
                        )

                        remember_terminal_zero_guard_literal_return_value(
                            mba,
                            int(site.const_value),
                        )
                    except Exception:
                        logger.debug(
                            "direct_terminal_lowering_group: failed to remember "
                            "terminal literal",
                            exc_info=True,
                        )
                    logger.debug(
                        "DTL_DIAG Phase4_RETURN_CONST: site[%d] anchor=%d "
                        "const=0x%016x -> direct stop",
                        site_idx,
                        site.anchor_serial,
                        int(site.const_value) & 0xFFFFFFFFFFFFFFFF,
                    )
                    per_site_first_clone.append(mba.qty - 1)
                    continue
                elif (
                    site.kind == ExitPathLoweringKind.CLONE_MATERIALIZER
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
                allow_terminal_tail_skip = bool(
                    getattr(site, "skip_terminal_control_tail", False)
                )
                for source_serial, template in zip(
                    clone_source_serials, site_templates
                ):
                    tail = getattr(template, "tail", None)
                    tail_is_conditional = (
                        tail is not None
                        and ida_hexrays.is_mcode_jcond(int(getattr(tail, "opcode", -1)))
                    )
                    if template.nsucc() != 1 and not (
                        allow_terminal_tail_skip
                        and template.nsucc() == 2
                        and tail_is_conditional
                    ):
                        logger.warning(
                            "direct_terminal_lowering_group: materializer blk[%d] "
                            "is not a 1-way template (nsucc=%d)",
                            source_serial,
                            template.nsucc(),
                        )
                        return False

                for idx, source_serial in enumerate(clone_source_serials):
                    template_blk = site_templates[idx]

                    # Clone instructions. Trailing gotos are re-inserted by the
                    # clone helper; a proven exit path may also drop the
                    # final conditional state guard and wire the clone straight
                    # to BLT_STOP.
                    instructions_to_copy = []
                    cur_ins = template_blk.head
                    while cur_ins is not None:
                        is_tail = cur_ins.next is None
                        if (
                            template_blk.nsucc() == 1
                            and template_blk.tail is not None
                            and template_blk.tail.opcode == ida_hexrays.m_goto
                            and is_tail
                        ):
                            break
                        if (
                            allow_terminal_tail_skip
                            and template_blk.nsucc() == 2
                            and template_blk.tail is not None
                            and is_tail
                            and ida_hexrays.is_mcode_jcond(
                                int(getattr(template_blk.tail, "opcode", -1))
                            )
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

    def _apply_reorder_blocks(
        self,
        dfs_block_order: tuple[int, ...],
        *,
        expected_old_to_new: dict[int, int] | None = None,
        expected_old_to_trampoline: dict[int, int] | None = None,
    ) -> bool:
        """Copy handler blocks to end of MBA in DFS order, remap all serial refs.

        Phase A: Copy each block in *dfs_block_order* to the end of the MBA
        (before BLT_STOP).  copy_block copies pred/succ from source.  We keep
        the new block's succset intact (it holds old handler serials that Phase B
        will remap) and clear only the predset.

        Step 0: Convert each old handler block into a 1-way trampoline
        (m_goto → new_serial).  External 2-way blocks (condition-chain check nodes) have
        the old handler serial as their fallthrough (serial+1).  IDA requires
        serial+1 to remain in the succset of BLT_2WAY blocks, so we leave those
        entries as-is in Phase B; the trampoline at the old serial correctly
        redirects execution to the new copy.

        Phase B: Walk every block that is NOT an old handler and remap its
        succset entries + mop_b / m_jtbl operands through old_to_new.  For
        BLT_2WAY blocks the fallthrough (serial+1) entry is kept verbatim; only
        explicit non-fallthrough targets are remapped.

        Phase C: Rebuild ALL predsets from scratch by walking succsets.  This
        guarantees bidirectional consistency.

        Args:
            dfs_block_order: Ordered block serials to copy.
            expected_old_to_new: Pre-computed old->new serial mapping from
                PatchPlan compilation. When provided, copy_block results are
                validated against these expected serials. A mismatch logs an
                error but falls back to the runtime serial.
        """
        mba = self.mba
        if not dfs_block_order:
            logger.warning("reorder_blocks: empty dfs_block_order")
            return False

        old_to_new: dict[int, int] = {}

        # Save BLT_STOP serial before Phase A — each copy_block(blk, qty-1) shifts
        # BLT_STOP by +1, so any handler block whose succset contains the old BLT_STOP
        # serial would be left pointing at whatever block now occupies that serial
        # (a copied handler) instead of the real BLT_STOP.  We remap this explicitly.
        old_blt_stop_serial = mba.qty - 1

        # Rebuild non-2WAY and 2WAY serials from live MBA state.  The
        # dfs_block_order was computed at strategy/plan time when certain blocks
        # were BLT_1WAY.  By apply time, LFG or other transforms may have
        # converted some blocks.  Filtering at runtime avoids serial mismatch.
        runtime_non_2way: list[int] = []
        runtime_2way: list[int] = []
        for s in dfs_block_order:
            blk = mba.get_mblock(s)
            if blk is None:
                logger.warning(
                    "reorder_blocks: blk[%d] not found, skipping",
                    s,
                )
                continue
            if blk.type == ida_hexrays.BLT_2WAY:
                runtime_2way.append(s)
                continue
            runtime_non_2way.append(s)

        if runtime_2way:
            logger.info(
                "reorder_blocks: %d BLT_2WAY blocks to copy with trampolines: %s",
                len(runtime_2way),
                runtime_2way[:20],
            )

        # ---- Phase A: Copy blocks to end in DFS order ----
        for old_serial in runtime_non_2way:
            old_blk = mba.get_mblock(old_serial)
            if old_blk is None:
                continue
            # Append before BLT_STOP — only shifts BLT_STOP, safe
            new_blk = copy_block_keep(mba, old_blk, mba.qty - 1)
            actual_serial = new_blk.serial
            # Diagnostic: compare against pre-computed serial from PatchPlan.
            # Mismatches are expected when LFG changes block types between plan
            # and apply time; the runtime serial is authoritative.
            if expected_old_to_new is not None and old_serial in expected_old_to_new:
                expected_serial = expected_old_to_new[old_serial]
                if actual_serial != expected_serial:
                    logger.debug(
                        "reorder_blocks Phase A: copy_block returned serial %d "
                        "for old=%d, expected %d (LFG-induced drift, using runtime)",
                        actual_serial,
                        old_serial,
                        expected_serial,
                    )
            old_to_new[old_serial] = actual_serial
            # CRITICAL: clear only predset — succset (pointing to old handler
            # serials) is kept; Phase B will remap those entries on the new block.
            new_blk.predset.clear()
            new_blk.build_lists(False)
            logger.debug(
                "reorder_blocks Phase A: copied blk[%d] -> blk[%d]",
                old_serial,
                new_blk.serial,
            )

        # ---- Phase A (2WAY): Copy handler-internal BLT_2WAY blocks + emit fallthrough trampolines ----
        # Track 2WAY copy info for post-copy succset fixup.
        runtime_2way_info: dict[
            int, tuple[int, int]
        ] = {}  # old_serial -> (copy_serial, tramp_serial)
        for old_serial in runtime_2way:
            old_blk = mba.get_mblock(old_serial)
            if old_blk is None:
                continue

            # 1. Copy the 2WAY block (appends before BLT_STOP)
            new_blk = copy_block_keep(mba, old_blk, mba.qty - 1)
            copy_serial = new_blk.serial
            new_blk.predset.clear()
            new_blk.build_lists(False)
            old_to_new[old_serial] = copy_serial

            if expected_old_to_new is not None and old_serial in expected_old_to_new:
                expected_serial = expected_old_to_new[old_serial]
                if copy_serial != expected_serial:
                    logger.debug(
                        "reorder_blocks Phase A (2WAY): copy serial %d for old=%d, expected %d",
                        copy_serial,
                        old_serial,
                        expected_serial,
                    )

            # 2. Emit BLT_1WAY fallthrough trampoline at mba.qty-1 (= copy_serial+1).
            # Strategy: copy a reference 1WAY block and overwrite its contents.
            # Find any existing BLT_1WAY block to use as template.
            ref_blk: ida_hexrays.mblock_t | None = None
            for _i in range(mba.qty - 1):
                _b = mba.get_mblock(_i)
                if _b is not None and _b.type == ida_hexrays.BLT_1WAY:
                    ref_blk = _b
                    break

            if ref_blk is None:
                logger.error(
                    "reorder_blocks Phase A (2WAY): no BLT_1WAY template found for "
                    "trampoline (old=%d, copy=%d) — skipping trampoline",
                    old_serial,
                    copy_serial,
                )
                continue

            tramp_blk = copy_block_keep(mba, ref_blk, mba.qty - 1)
            tramp_serial = tramp_blk.serial  # should be copy_serial + 1

            if (
                expected_old_to_trampoline is not None
                and old_serial in expected_old_to_trampoline
            ):
                expected_tramp = expected_old_to_trampoline[old_serial]
                if tramp_serial != expected_tramp:
                    logger.debug(
                        "reorder_blocks Phase A (2WAY): trampoline serial %d for old=%d, expected %d",
                        tramp_serial,
                        old_serial,
                        expected_tramp,
                    )

            runtime_2way_info[old_serial] = (copy_serial, tramp_serial)

            # Overwrite trampoline content: single m_goto -> old_serial+1 (pre-remap)
            # Phase B will remap this target through old_to_new.
            fallthrough_target = old_serial + 1
            # Clear all existing instructions
            insn = tramp_blk.head
            while insn is not None:
                nxt = insn.next
                tramp_blk.make_nop(insn)
                insn = nxt

            # Insert m_goto
            goto_insn = ida_hexrays.minsn_t(old_blk.start)
            goto_insn.opcode = ida_hexrays.m_goto
            goto_insn.l.make_blkref(fallthrough_target)
            goto_insn.r.erase()
            goto_insn.d.erase()
            tramp_blk.insert_into_block(goto_insn, tramp_blk.tail)
            tramp_blk.type = ida_hexrays.BLT_1WAY
            # Set trampoline address range to the source block's range so it
            # stays within function boundaries (avoids INTERR 50870).
            # The trampoline is copied from an arbitrary BLT_1WAY template
            # whose address may be outside the handler's range.
            tramp_blk.start = old_blk.start
            tramp_blk.end = old_blk.end
            tramp_blk.succset.clear()
            tramp_blk.succset.push_back(fallthrough_target)
            tramp_blk.predset.clear()
            tramp_blk.build_lists(False)

            logger.debug(
                "reorder_blocks Phase A (2WAY): blk[%d] -> copy blk[%d], trampoline blk[%d] -> blk[%d]",
                old_serial,
                copy_serial,
                tramp_serial,
                fallthrough_target,
            )

        if runtime_2way:
            logger.info(
                "reorder_blocks Phase A (2WAY): copied %d BLT_2WAY blocks with fallthrough trampolines",
                len(runtime_2way),
            )

        # ---- Phase A fixup: Remap 2WAY copy succsets and mop_b operands ----
        # copy_block copies the old block's succset verbatim.  For a BLT_2WAY
        # block the old succset is [old_serial+1, old_conditional_target].
        # Phase B protects the *implicit fallthrough* at copy_serial+1 but the
        # succset still holds old_serial+1, which Phase B would incorrectly
        # remap.  Fix: replace old_serial+1 -> tramp_serial (= copy_serial+1)
        # in both the succset and the tail mop_b operand pointing at the old
        # fallthrough.
        for old_serial, (copy_serial, tramp_serial) in runtime_2way_info.items():
            copy_blk = mba.get_mblock(copy_serial)
            if copy_blk is None:
                continue
            old_fallthrough = old_serial + 1
            # Fix succset: replace old fallthrough with trampoline serial
            new_succs: list[int] = []
            for _si in range(copy_blk.succset.size()):
                s = copy_blk.succset[_si]
                if s == old_fallthrough:
                    new_succs.append(tramp_serial)
                else:
                    new_succs.append(s)
            copy_blk.succset.clear()
            for s in new_succs:
                copy_blk.succset.push_back(s)
            logger.debug(
                "reorder_blocks Phase A fixup: blk[%d] (copy of %d) succset old_ft=%d -> tramp=%d, new_succs=%s",
                copy_serial,
                old_serial,
                old_fallthrough,
                tramp_serial,
                new_succs,
            )

        if not old_to_new:
            logger.warning("reorder_blocks: no blocks copied")
            return False

        logger.info(
            "reorder_blocks Phase A: copied %d blocks (%d non-2WAY, %d 2WAY)",
            len(old_to_new),
            len(runtime_non_2way),
            len(runtime_2way),
        )

        # PRE-TRAMPOLINE diagnostic: count m_nop-with-operands BEFORE Step 0
        _pre_nop_count = 0
        _m_nop_pre = ida_hexrays.m_nop
        _mop_z_pre = ida_hexrays.mop_z
        for _pi in range(mba.qty):
            _pblk = mba.get_mblock(_pi)
            if _pblk is None:
                continue
            _pins = _pblk.head
            while _pins is not None:
                if _pins.opcode == _m_nop_pre:
                    _pl = _pins.l is not None and _pins.l.t != _mop_z_pre
                    _pr = _pins.r is not None and _pins.r.t != _mop_z_pre
                    _pd = _pins.d is not None and _pins.d.t != _mop_z_pre
                    if _pl or _pr or _pd:
                        _pre_nop_count += 1
                _pins = _pins.next
        logger.error(
            "DIAG PRE-TRAMPOLINE: %d m_nop-with-operands BEFORE Step 0, old_serials=%s",
            _pre_nop_count,
            sorted(old_to_new.keys())[:10],
        )

        # old_serials identifies the trampoline blocks (Step 0). Compute it from
        # the handler serials only — before adding the BLT_STOP remap entry.
        old_serials = set(old_to_new.keys())

        # Extend old_to_new with the BLT_STOP serial shift so Phase B's generic
        # remap logic (`old_to_new.get(s, s)`) correctly updates any succset entry
        # or mop_b operand that references the old BLT_STOP serial.  Must happen
        # AFTER old_serials is built so Phase B does not mistakenly skip the block
        # now occupying the old BLT_STOP serial (it is a copied handler, not a
        # trampoline).
        new_blt_stop_serial = mba.qty - 1
        if new_blt_stop_serial != old_blt_stop_serial:
            old_to_new[old_blt_stop_serial] = new_blt_stop_serial
            logger.debug(
                "reorder_blocks: BLT_STOP shifted %d -> %d",
                old_blt_stop_serial,
                new_blt_stop_serial,
            )

        # ---- Step 0: Convert old handler blocks to trampolines ----
        # External 2-way blocks need their fallthrough (serial+1) to stay at
        # the old handler serial — IDA requires serial+1 in succset for BLT_2WAY.
        # Converting old handlers to m_goto trampolines lets those fallthroughs
        # correctly redirect execution to the new copy.
        # Iterate only over original handler serials (old_serials), NOT
        # old_to_new — old_to_new now also contains the BLT_STOP remap entry,
        # which must NOT be converted into a trampoline.
        for old_serial in old_serials:
            new_serial = old_to_new[old_serial]
            old_blk = mba.get_mblock(old_serial)
            if old_blk is None:
                continue
            tail = old_blk.tail
            if tail is None:
                continue
            # NOP all intermediate instructions; tail becomes the sole insn.
            # Use make_nop (not raw opcode=m_nop) to clear iprops — an
            # is_assert flag surviving an opcode change triggers INTERR 52123.
            insn = old_blk.head
            while insn is not None and insn is not tail:
                next_insn = insn.next
                old_blk.make_nop(insn)
                insn = next_insn
            # Convert tail to unconditional goto → new serial.
            # make_nop first to clear iprops (avoids INTERR 52123), then
            # set the goto opcode and operand.
            old_blk.make_nop(tail)
            tail.opcode = ida_hexrays.m_goto
            tail.l.make_blkref(new_serial)
            tail.r.erase()
            tail.d.erase()
            # Update block type and succset
            old_blk.type = ida_hexrays.BLT_1WAY
            old_blk.succset.clear()
            old_blk.succset.push_back(new_serial)
            old_blk.build_lists(False)
            logger.debug(
                "reorder_blocks Step 0: blk[%d] -> trampoline -> blk[%d]",
                old_serial,
                new_serial,
            )

        # ---- Phase B: Remap succsets + instruction operands ----
        # For BLT_2WAY blocks the fallthrough is implicitly serial+1.  The IDA
        # contract requires serial+1 to appear in succset, so we keep that entry
        # as-is; the trampoline at that serial (if it was an old handler) handles
        # the redirect.  New handler blocks (produced in Phase A) also get their
        # succsets remapped here.
        for i in range(mba.qty):
            blk = mba.get_mblock(i)
            if blk is None:
                continue

            if blk.serial in old_serials:
                # Trampolines already set up in Step 0; skip.
                continue

            # Protect implicit fallthrough (serial+1) from being remapped when
            # the tail instruction has no mop_b branch target.  In those cases
            # IDA derives outs as {serial+1} and there is no operand to remap,
            # so remapping the succset alone would create a CFG_50860 mismatch.
            # Rules:
            # - BLT_2WAY: always protect serial+1 (explicit branch uses mop_b d,
            #   which the instruction-remap loop handles; fallthrough is separate).
            # - null tail: no instruction → fallthrough to serial+1.
            # - m_ret tail: IDA derives {BLT_STOP} — do NOT protect serial+1;
            #   let the BLT_STOP serial remap in old_to_new fix the succset.
            # - Any other tail without mop_b (m_nop, m_call, m_icall, …): IDA
            #   derives {serial+1}; protect it.
            tail = blk.tail
            if tail is None or blk.type == ida_hexrays.BLT_2WAY:
                has_implicit_fallthrough = True
            elif tail.opcode == ida_hexrays.m_ret:
                has_implicit_fallthrough = False
            else:
                # Protect when no mop_b branch target is present in l/r/d.
                has_implicit_fallthrough = not any(
                    mop is not None and mop.t == ida_hexrays.mop_b
                    for mop in (tail.l, tail.r, tail.d)
                )
            fallthrough = (blk.serial + 1) if has_implicit_fallthrough else None

            new_succs: list[int] = []
            for s in list(blk.succset):
                if s == fallthrough:
                    new_succs.append(s)  # physical fallthrough: keep
                else:
                    new_succs.append(old_to_new.get(s, s))  # remap
            blk.succset.clear()
            for s in new_succs:
                blk.succset.push_back(s)

            # Remap mop_b operands in all instructions
            insn = blk.head
            while insn is not None:
                for mop in (insn.l, insn.r, insn.d):
                    if mop is not None and mop.t == ida_hexrays.mop_b:
                        if mop.b in old_to_new:
                            mop.make_blkref(old_to_new[mop.b])
                # m_jtbl: targets stored in insn.r.c.targets (mcases_t / intvec_t)
                if insn.opcode == ida_hexrays.m_jtbl:
                    if (
                        insn.r is not None
                        and insn.r.t == ida_hexrays.mop_c
                        and insn.r.c is not None
                    ):
                        targets = insn.r.c.targets
                        for idx in range(targets.size()):
                            old_val = targets[idx]
                            if old_val in old_to_new:
                                targets[idx] = old_to_new[old_val]
                insn = insn.next

        # ---- Phase C: Rebuild ALL predsets from current succsets ----
        # Clears every predset then repopulates from succsets — guarantees
        # bidirectional consistency without manually tracking every edge.
        for i in range(mba.qty):
            blk = mba.get_mblock(i)
            if blk is not None:
                blk.predset.clear()
        for i in range(mba.qty):
            blk = mba.get_mblock(i)
            if blk is None:
                continue
            for s in list(blk.succset):
                target = mba.get_mblock(s)
                if target is not None:
                    target.predset.push_back(i)

        mba.mark_chains_dirty()

        logger.debug("reorder_blocks: operand erase applied to all m_nop trampolines")

        logger.info(
            "reorder_blocks: completed — %d blocks remapped, mba.qty=%d",
            len(old_to_new),
            mba.qty,
        )
        return True

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
            if expected_serial is not None:
                self._begin_patch_block_creation(expected_serial)
            new_blk = create_standalone_block(
                src_blk,
                [],
                target_serial=new_target,
                is_0_way=False,
                verify=False,
            )
            if expected_serial is not None:
                self._bind_patch_block_creation(expected_serial, new_blk.serial)
            if new_blk.serial != expected_serial:
                logger.info(
                    "edge_split_trampoline: created blk[%d], expected blk[%d] "
                    "(serial drift from prior mod); recording remap",
                    new_blk.serial,
                    expected_serial,
                )
            new_stop_serial = mba.qty - 1
            for pred_serial in old_stop_pred_serials:
                pred_blk = mba.get_mblock(pred_serial)
                if pred_blk is None or pred_blk.serial == new_blk.serial:
                    continue
                if pred_blk.nsucc() != 1 or pred_blk.succ(0) != new_blk.serial:
                    continue
                if not change_1way_block_successor(
                    pred_blk, new_stop_serial, verify=False
                ):
                    logger.warning(
                        "edge_split_trampoline: failed to relocate stop predecessor blk[%d] -> blk[%d]",
                        pred_blk.serial,
                        new_stop_serial,
                    )
                    return False

            if not change_1way_block_successor(
                via_pred_blk, new_blk.serial, verify=False
            ):
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
        sorted_mods: list[QueuedModification],
    ) -> tuple[list[QueuedModification], int]:
        """Reject unsupported standalone block creation before live mutation."""
        filtered_mods: list[QueuedModification] = []
        pre_rejected = 0

        for mod in sorted_mods:
            if mod.mod_type != ModificationType.BLOCK_CREATE_WITH_REDIRECT:
                filtered_mods.append(mod)
                continue
            if self._check_create_and_redirect_preconditions(
                source_block_serial=mod.block_serial,
                final_target_serial=mod.final_target,
                old_target_serial=mod.old_target,
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
        sorted_mods: list[QueuedModification],
    ) -> tuple[list[QueuedModification], int]:
        """Reject trampoline edits with illegal live preconditions before mutation."""
        filtered_mods: list[QueuedModification] = []
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
        sorted_mods: list[QueuedModification],
    ) -> tuple[list[QueuedModification], int]:
        """Reject unsupported duplicate-block edits before live mutation."""
        filtered_mods: list[QueuedModification] = []
        pre_rejected = 0

        for mod in sorted_mods:
            if mod.mod_type != ModificationType.BLOCK_DUPLICATE_AND_REDIRECT:
                filtered_mods.append(mod)
                continue
            if self._check_duplicate_block_preconditions(
                source_block_serial=mod.block_serial,
                pred_serial=mod.via_pred,
                target_serial=mod.new_target,
                conditional_target=mod.conditional_target,
                fallthrough_target=mod.fallthrough_target,
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

    def _pre_reject_clone_conditional_as_goto(
        self,
        sorted_mods: list[QueuedModification],
    ) -> tuple[list[QueuedModification], int]:
        """Reject unsupported clone-as-goto edits before live mutation."""
        filtered_mods: list[QueuedModification] = []
        pre_rejected = 0

        for mod in sorted_mods:
            if mod.mod_type not in (
                ModificationType.CLONE_CONDITIONAL_AS_GOTO,
                ModificationType.CLONE_CONDITIONAL_AS_GOTO_FROM_BRANCH_ARM,
            ):
                filtered_mods.append(mod)
                continue
            pred_topology = (
                "two_way_branch_arm"
                if mod.mod_type
                == ModificationType.CLONE_CONDITIONAL_AS_GOTO_FROM_BRANCH_ARM
                else "one_way"
            )
            if self._check_clone_conditional_as_goto_preconditions(
                source_block_serial=mod.block_serial,
                pred_serial=mod.via_pred,
                goto_target_serial=mod.new_target,
                pred_topology=pred_topology,
            ):
                filtered_mods.append(mod)
                continue

            pre_rejected += 1
            logger.warning(
                "Pre-rejecting %s before live apply: %s",
                mod.mod_type.name,
                mod.description,
            )

        if pre_rejected:
            logger.warning(
                "Pre-rejected %d clone_conditional_as_goto modification(s) before live apply",
                pre_rejected,
            )

        return filtered_mods, pre_rejected

    def _check_create_and_redirect_preconditions(
        self,
        *,
        source_block_serial: int | None,
        final_target_serial: int | None,
        old_target_serial: int | None = None,
    ) -> bool:
        """Validate live topology for create-and-redirect without mutating the MBA."""
        if (
            self.mba is None
            or source_block_serial is None
            or final_target_serial is None
        ):
            logger.warning(
                "create_and_redirect: incomplete parameters src=%s target=%s",
                source_block_serial,
                final_target_serial,
            )
            return False

        source_blk = self.mba.get_mblock(source_block_serial)
        target_blk = (
            self.mba.get_mblock(final_target_serial)
            if _is_live_block_serial(self.mba, final_target_serial)
            else None
        )
        if source_blk is None or target_blk is None:
            if source_blk is not None and not _is_live_block_serial(
                self.mba,
                final_target_serial,
            ):
                logger.debug(
                    "create_and_redirect: allowing future target blk[%s] "
                    "during pre-reject validation (current qty=%d)",
                    final_target_serial,
                    int(getattr(self.mba, "qty", 0) or 0),
                )
            else:
                logger.warning(
                    "create_and_redirect: missing block src=%s target=%s",
                    source_block_serial,
                    final_target_serial,
                )
                return False
        if source_blk is None:
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

        nsucc = int(source_blk.nsucc())
        if nsucc == 1:
            return True
        if nsucc == 2:
            if old_target_serial is None:
                logger.warning(
                    "create_and_redirect: 2-way src blk[%d] requires old_target_serial",
                    source_blk.serial,
                )
                return False
            tail = source_blk.tail
            if tail is None or not ida_hexrays.is_mcode_jcond(int(tail.opcode)):
                logger.warning(
                    "create_and_redirect: 2-way src blk[%d] tail is not m_jcnd",
                    source_blk.serial,
                )
                return False
            try:
                cond_target = int(tail.d.b)
            except Exception:
                logger.warning(
                    "create_and_redirect: 2-way src blk[%d] m_jcnd target unreadable",
                    source_blk.serial,
                )
                return False
            if cond_target != int(old_target_serial):
                logger.warning(
                    "create_and_redirect: 2-way src blk[%d] cond arm=%d != "
                    "old_target=%d (fallthrough arm not supported)",
                    source_blk.serial,
                    cond_target,
                    int(old_target_serial),
                )
                return False
            return True

        logger.warning(
            "create_and_redirect: src blk[%d] has unsupported nsucc=%d",
            source_blk.serial,
            nsucc,
        )
        return False

    def _check_clone_conditional_as_goto_preconditions(
        self,
        *,
        source_block_serial: int | None,
        pred_serial: int | None,
        goto_target_serial: int | None,
        pred_topology: str = "one_way",
        pred_arm: int | None = None,
    ) -> bool:
        """Validate FixPredecessor clone-as-goto topology without mutation.

        ``pred_topology`` selects the predecessor-side check.  ``"one_way"``
        (default) requires ``pred.nsucc() == 1`` and ``pred.succ(0) == source``
        — the legacy live shape.  ``"two_way_branch_arm"`` instead requires
        ``pred.nsucc() == 2`` and validates that ``pred_arm`` reaches the
        source.
        """
        if (
            self.mba is None
            or source_block_serial is None
            or pred_serial is None
            or goto_target_serial is None
        ):
            logger.warning(
                "clone_conditional_as_goto: incomplete parameters src=%s pred=%s target=%s",
                source_block_serial,
                pred_serial,
                goto_target_serial,
            )
            return False

        source_blk = self.mba.get_mblock(source_block_serial)
        pred_blk = self.mba.get_mblock(pred_serial)
        old_stop_serial = int(self.mba.qty) - 1
        future_stop_serial = int(self.mba.qty)
        effective_target_serial = (
            old_stop_serial
            if int(goto_target_serial) == future_stop_serial
            else int(goto_target_serial)
        )
        target_blk = self.mba.get_mblock(effective_target_serial)

        if source_blk is None or pred_blk is None or target_blk is None:
            logger.warning(
                "clone_conditional_as_goto: missing block src=%s pred=%s target=%s",
                source_block_serial,
                pred_serial,
                goto_target_serial,
            )
            return False

        if source_blk.nsucc() != 2:
            logger.warning(
                "clone_conditional_as_goto: src blk[%d] has nsucc=%d, expected 2",
                source_blk.serial,
                source_blk.nsucc(),
            )
            return False
        if source_blk.tail is None or not ida_hexrays.is_mcode_jcond(
            source_blk.tail.opcode
        ):
            logger.warning(
                "clone_conditional_as_goto: src blk[%d] has non-conditional tail",
                source_blk.serial,
            )
            return False
        if source_blk.tail.d.t != ida_hexrays.mop_b:
            logger.warning(
                "clone_conditional_as_goto: src blk[%d] conditional tail lacks blkref operand",
                source_blk.serial,
            )
            return False

        source_successors = {
            int(source_blk.succ(idx)) for idx in range(int(source_blk.nsucc()))
        }
        conditional_target = int(source_blk.tail.d.b)
        if conditional_target not in source_successors:
            logger.warning(
                "clone_conditional_as_goto: conditional target blk[%d] not in src successors %s",
                conditional_target,
                sorted(source_successors),
            )
            return False
        if effective_target_serial == int(source_blk.serial):
            logger.warning(
                "clone_conditional_as_goto: rejecting self-loop target blk[%d]",
                effective_target_serial,
            )
            return False
        if effective_target_serial not in source_successors:
            logger.warning(
                "clone_conditional_as_goto: target blk[%d] not in src successors %s",
                effective_target_serial,
                sorted(source_successors),
            )
            return False

        if pred_topology == "one_way":
            if pred_blk.nsucc() != 1:
                logger.warning(
                    "clone_conditional_as_goto: pred blk[%d] has nsucc=%d, expected 1",
                    pred_blk.serial,
                    pred_blk.nsucc(),
                )
                return False
            if pred_blk.succ(0) != source_blk.serial:
                logger.warning(
                    "clone_conditional_as_goto: pred blk[%d] does not target src blk[%d]",
                    pred_blk.serial,
                    source_blk.serial,
                )
                return False
        elif pred_topology == "two_way_branch_arm":
            if pred_blk.nsucc() != 2:
                logger.warning(
                    "clone_conditional_as_goto_from_branch_arm: pred blk[%d] "
                    "has nsucc=%d, expected 2",
                    pred_blk.serial,
                    pred_blk.nsucc(),
                )
                return False
            if pred_arm not in (0, 1):
                logger.warning(
                    "clone_conditional_as_goto_from_branch_arm: pred blk[%d] "
                    "has invalid pred_arm=%s",
                    pred_blk.serial,
                    pred_arm,
                )
                return False
            if (
                pred_blk.tail is None
                or pred_blk.tail.d is None
                or pred_blk.tail.d.t != ida_hexrays.mop_b
                or not ida_hexrays.is_mcode_jcond(pred_blk.tail.opcode)
            ):
                logger.warning(
                    "clone_conditional_as_goto_from_branch_arm: pred blk[%d] "
                    "does not end with a conditional branch",
                    pred_blk.serial,
                )
                return False
            if pred_arm == 1 and int(pred_blk.tail.d.b) != int(source_blk.serial):
                actual_d = (
                    int(pred_blk.tail.d.b)
                    if pred_blk.tail is not None and pred_blk.tail.d is not None
                    else None
                )
                logger.warning(
                    "clone_conditional_as_goto_from_branch_arm: pred blk[%d] "
                    "explicit branch arm targets %s, expected source blk[%d]",
                    pred_blk.serial,
                    actual_d,
                    source_blk.serial,
                )
                return False
            if pred_arm == 0:
                fallthrough_target = _get_fallthrough_successor_serial(pred_blk)
                if fallthrough_target is None or int(fallthrough_target) != int(
                    source_blk.serial
                ):
                    logger.warning(
                        "clone_conditional_as_goto_from_branch_arm: pred blk[%d] "
                        "fallthrough arm targets %s, expected source blk[%d]",
                        pred_blk.serial,
                        fallthrough_target,
                        source_blk.serial,
                    )
                    return False
        else:
            logger.warning(
                "clone_conditional_as_goto: unknown pred_topology=%r",
                pred_topology,
            )
            return False

        return True

    def _check_duplicate_block_preconditions(
        self,
        *,
        source_block_serial: int | None,
        pred_serial: int | None,
        target_serial: int | None,
        conditional_target: int | None = None,
        fallthrough_target: int | None = None,
    ) -> bool:
        """Validate duplicate-and-redirect topology without mutating the MBA."""
        if self.mba is None or source_block_serial is None or pred_serial is None:
            logger.warning(
                "duplicate_block: incomplete parameters src=%s pred=%s target=%s",
                source_block_serial,
                pred_serial,
                target_serial,
            )
            return False

        source_blk = self.mba.get_mblock(source_block_serial)
        pred_blk = self.mba.get_mblock(pred_serial)
        target_blk = (
            self.mba.get_mblock(target_serial) if target_serial is not None else None
        )
        conditional_blk = (
            self.mba.get_mblock(conditional_target)
            if conditional_target is not None
            else None
        )
        fallthrough_blk = (
            self.mba.get_mblock(fallthrough_target)
            if fallthrough_target is not None
            else None
        )

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
        if conditional_target is not None and conditional_blk is None:
            logger.warning(
                "duplicate_block: missing conditional target blk[%s]",
                conditional_target,
            )
            return False
        if fallthrough_target is not None and fallthrough_blk is None:
            logger.warning(
                "duplicate_block: missing fallthrough target blk[%s]",
                fallthrough_target,
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
            if source_blk.tail is None or not ida_hexrays.is_mcode_jcond(
                source_blk.tail.opcode
            ):
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
            resolved_conditional = (
                conditional_target
                if conditional_target is not None
                else source_blk.tail.d.b
            )
            resolved_fallthrough = (
                fallthrough_target
                if fallthrough_target is not None
                else next(
                    (
                        source_blk.succ(i)
                        for i in range(source_blk.nsucc())
                        if source_blk.succ(i) != source_blk.tail.d.b
                    ),
                    None,
                )
            )
            if resolved_fallthrough is None:
                logger.warning(
                    "duplicate_block: src blk[%d] missing fallthrough successor",
                    source_blk.serial,
                )
                return False
            if resolved_conditional == resolved_fallthrough:
                logger.warning(
                    "duplicate_block: src blk[%d] has identical conditional/fallthrough target %d",
                    source_blk.serial,
                    resolved_conditional,
                )
                return False
        elif conditional_target is not None or fallthrough_target is not None:
            logger.warning(
                "duplicate_block: src blk[%d] is not 2-way but conditional targets were provided",
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
            if pred_blk.tail is None or not ida_hexrays.is_mcode_jcond(
                pred_blk.tail.opcode
            ):
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
        validate_new_target: bool = True,
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
        try:
            src_blk = mba.get_mblock(source_block_serial)
            via_pred_blk = mba.get_mblock(via_pred)
            target_blk = mba.get_mblock(new_target) if validate_new_target else None
        except RuntimeError as exc:
            logger.warning(
                "edge_split_trampoline: live block probe failed "
                "src=%s pred=%s old=%s new=%s validate_new_target=%s: %s",
                source_block_serial,
                via_pred,
                old_target,
                new_target,
                validate_new_target,
                exc,
            )
            return False

        if (
            src_blk is None
            or via_pred_blk is None
            or (validate_new_target and target_blk is None)
        ):
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

        if src_blk.nsucc() != 1:
            logger.warning(
                "edge_split_trampoline: src block %d has nsucc=%d, expected 1",
                src_blk.serial,
                src_blk.nsucc(),
            )
            return False
        # via_pred must be a 1-way block.  Its tail does NOT need to be m_goto —
        # change_1way_block_successor handles m_call, m_ijmp, None, etc. by
        # inserting an explicit goto before rewiring.
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
        source_new_target: int | None = None,
    ) -> bool:
        """Clone ``blk`` and rewire ``via_pred``'s edge from ``blk`` to the clone.

        The clone then has its successor changed from ``old_target`` to
        ``new_target``.  The original ``blk`` keeps all other predecessors and
        its original successor.

        Args:
            blk: The block to clone (src_block).
            old_target: Current successor on blk being replaced on the clone.
            new_target: New successor for the clone.
            via_pred: Predecessor whose edge is rewired to the clone.
            clone_until: Optional final block in a strict 1-way corridor clone.

        Returns:
            True on success, False on failure.
        """
        if clone_until is not None:
            return self._apply_edge_redirect_via_pred_split_corridor(
                blk=blk,
                old_target=old_target,
                new_target=new_target,
                via_pred=via_pred,
                clone_until=clone_until,
                source_new_target=source_new_target,
            )

        mba = self.mba

        # ── Legality gate ──────────────────────────────────────────────
        # Both blocks must have explicit tails with expected opcodes.
        if blk.tail is None or blk.tail.opcode != ida_hexrays.m_goto:
            logger.warning(
                "EDGE_SPLIT_ILLEGAL_PRECOND: src blk[%d] tail is not m_goto "
                "(old_target=%d, new_target=%d)",
                blk.serial,
                old_target,
                new_target,
            )
            return False

        # via_pred tail does NOT need to be m_goto — change_1way_block_successor
        # (used below for the actual rewire) handles m_call, m_ijmp, None, etc.
        # by inserting an explicit goto before rewiring.
        via_pred_blk_pre = mba.get_mblock(via_pred)

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
                    via_pred,
                    blk.serial,
                    old_target,
                    new_target,
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
                blk.serial,
                new_target,
            )
            return False

        via_pred_blk = mba.get_mblock(via_pred)
        if via_pred_blk is None:
            logger.warning("via_pred block %d not found", via_pred)
            return False
        if via_pred_blk.nsucc() != 1:
            logger.warning(
                "via_pred block %d has %d successors, expected 1",
                via_pred,
                via_pred_blk.nsucc(),
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
                    via_pred,
                    new_target,
                )
                return False

            mba.mark_chains_dirty()

            logger.debug(
                "edge_redirect_via_pred_split: done — pred=%d -> %d "
                "(original blk=%d -> %d preserved)",
                via_pred,
                new_target,
                blk.serial,
                old_target,
            )
            return True

        except Exception as e:
            logger.error(
                "Exception in edge_redirect_via_pred_split for block %d: %s",
                blk.serial,
                e,
            )
            import traceback

            logger.error("Traceback: %s", traceback.format_exc())
            return False

    def _apply_edge_redirect_via_pred_split_corridor(
        self,
        *,
        blk: "ida_hexrays.mblock_t",
        old_target: int,
        new_target: int,
        via_pred: int,
        clone_until: int,
        source_new_target: int | None = None,
    ) -> bool:
        """Clone a strict 1-way corridor and redirect one predecessor to it.

        The live use-case is a shared suffix handoff where ``via_pred`` must
        reach a private copy of ``blk .. clone_until`` while the original
        corridor remains available to other predecessors.
        """
        mba = self.mba
        if mba is None:
            return False

        via_pred_blk = mba.get_mblock(via_pred)
        if via_pred_blk is None:
            logger.warning(
                "edge_redirect_via_pred_split corridor: via_pred blk[%d] not found",
                via_pred,
            )
            return False
        if via_pred_blk.nsucc() != 1:
            logger.warning(
                "edge_redirect_via_pred_split corridor: via_pred blk[%d] has nsucc=%d, expected 1",
                via_pred_blk.serial,
                via_pred_blk.nsucc(),
            )
            return False
        if via_pred_blk.succ(0) != blk.serial:
            logger.warning(
                "edge_redirect_via_pred_split corridor: via_pred blk[%d] targets blk[%d], expected src blk[%d]",
                via_pred_blk.serial,
                via_pred_blk.succ(0),
                blk.serial,
            )
            return False

        if blk.nsucc() != 1:
            logger.warning(
                "edge_redirect_via_pred_split corridor: src blk[%d] has nsucc=%d, expected 1",
                blk.serial,
                blk.nsucc(),
            )
            return False
        current_target = blk.succ(0)
        if current_target != old_target:
            if int(clone_until) != blk.serial:
                logger.warning(
                    "edge_redirect_via_pred_split corridor: src blk[%d] does not start old_target=%d (succ0=%d)",
                    blk.serial,
                    old_target,
                    current_target,
                )
                return False
            logger.info(
                "edge_redirect_via_pred_split corridor: accepting one-block old_target drift src=%d planned_old=%d live_old=%d",
                blk.serial,
                old_target,
                current_target,
            )

        corridor_serials = [blk.serial]
        corridor_seen = {blk.serial}
        cursor = blk
        while cursor.serial != int(clone_until):
            if cursor.nsucc() != 1:
                logger.warning(
                    "edge_redirect_via_pred_split corridor: interior blk[%d] has nsucc=%d, expected 1",
                    cursor.serial,
                    cursor.nsucc(),
                )
                return False
            next_serial = cursor.succ(0)
            if next_serial in corridor_seen:
                logger.warning(
                    "edge_redirect_via_pred_split corridor: cycle detected while walking blk[%d] -> blk[%d]",
                    cursor.serial,
                    next_serial,
                )
                return False
            next_blk = mba.get_mblock(next_serial)
            if next_blk is None:
                logger.warning(
                    "edge_redirect_via_pred_split corridor: missing next blk[%d] from blk[%d]",
                    next_serial,
                    cursor.serial,
                )
                return False
            corridor_serials.append(next_serial)
            corridor_seen.add(next_serial)
            cursor = next_blk

        corridor_templates = [mba.get_mblock(serial) for serial in corridor_serials]
        if any(template is None for template in corridor_templates):
            logger.warning(
                "edge_redirect_via_pred_split corridor: missing template in %s",
                corridor_serials,
            )
            return False
        if any(
            template.nsucc() != 1
            for template in corridor_templates
            if template is not None
        ):
            logger.warning(
                "edge_redirect_via_pred_split corridor: non-1way block present in corridor %s",
                corridor_serials,
            )
            return False
        if new_target == corridor_serials[-1]:
            logger.warning(
                "edge_redirect_via_pred_split corridor: rejecting self-loop final target %d",
                new_target,
            )
            return False

        cloned_serials: list[int] = []
        try:
            for index, template_blk in enumerate(corridor_templates):
                assert template_blk is not None
                is_last = index == len(corridor_templates) - 1
                placeholder_target = (
                    int(new_target) if is_last else int(corridor_serials[index + 1])
                )

                instructions_to_copy: list[ida_hexrays.minsn_t] = []
                cur_ins = template_blk.head
                while cur_ins is not None:
                    is_trailing_goto = (
                        template_blk.tail is not None
                        and template_blk.tail.opcode == ida_hexrays.m_goto
                        and cur_ins.next is None
                    )
                    if is_trailing_goto:
                        break
                    cloned_ins = ida_hexrays.minsn_t(cur_ins)
                    cloned_ins.setaddr(mba.entry_ea)
                    instructions_to_copy.append(cloned_ins)
                    cur_ins = cur_ins.next

                cloned_blk = create_standalone_block(
                    template_blk,
                    instructions_to_copy,
                    target_serial=placeholder_target,
                    is_0_way=False,
                    verify=False,
                )
                cloned_serials.append(cloned_blk.serial)

            for index in range(len(cloned_serials) - 1):
                cloned_blk = mba.get_mblock(cloned_serials[index])
                next_clone_serial = cloned_serials[index + 1]
                if cloned_blk is None:
                    return False
                if not change_1way_block_successor(
                    cloned_blk,
                    next_clone_serial,
                    verify=False,
                ):
                    logger.warning(
                        "edge_redirect_via_pred_split corridor: failed to wire clone blk[%d] -> blk[%d]",
                        cloned_serials[index],
                        next_clone_serial,
                    )
                    return False

            final_clone_blk = mba.get_mblock(cloned_serials[-1])
            if final_clone_blk is None:
                return False
            if final_clone_blk.succ(0) != int(new_target):
                if not change_1way_block_successor(
                    final_clone_blk,
                    int(new_target),
                    verify=False,
                ):
                    logger.warning(
                        "edge_redirect_via_pred_split corridor: failed to retarget final clone blk[%d] -> blk[%d]",
                        final_clone_blk.serial,
                        int(new_target),
                    )
                    return False

            if not change_1way_block_successor(
                via_pred_blk,
                cloned_serials[0],
                verify=False,
            ):
                logger.warning(
                    "edge_redirect_via_pred_split corridor: failed to redirect via_pred blk[%d] -> clone blk[%d]",
                    via_pred_blk.serial,
                    cloned_serials[0],
                )
                return False

            if source_new_target is not None:
                if not change_1way_block_successor(
                    blk,
                    int(source_new_target),
                    verify=False,
                ):
                    logger.warning(
                        "edge_redirect_via_pred_split corridor: failed to retarget original src blk[%d] -> blk[%d]",
                        blk.serial,
                        int(source_new_target),
                    )
                    return False

            mba.mark_chains_dirty()
            logger.info(
                "edge_redirect_via_pred_split corridor: pred=%d src=%d corridor=%s clones=%s final_target=%d source_target=%s",
                via_pred_blk.serial,
                blk.serial,
                corridor_serials,
                cloned_serials,
                int(new_target),
                int(source_new_target) if source_new_target is not None else None,
            )
            return True
        except Exception as exc:
            logger.error(
                "Exception in edge_redirect_via_pred_split corridor for src=%d clone_until=%d: %s",
                blk.serial,
                int(clone_until),
                exc,
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
        old_target: int | None = None,
        description: str = "",
    ) -> None:
        """Apply a change to a conditional jump's target immediately."""
        blk = self.mba.get_mblock(block_serial)
        if blk is None:
            logger.warning("Block %d not found", block_serial)
            return

        logger.debug(
            "Immediate target change: block %d old_target=%s -> %d",
            block_serial,
            old_target,
            new_target,
        )
        if self._apply_target_change(blk, new_target, old_target):
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

        logger.debug(
            "Immediate convert to goto: block %d -> %d", block_serial, goto_target
        )
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

        logger.debug(
            "Immediate insn remove: block %d, ea=%s", block_serial, hex(insn_ea)
        )
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

    def queue_zero_state_write(
        self,
        block_serial: int,
        insn_ea: int,
        description: str = "",
    ) -> None:
        """Zero the source operand of a state variable write immediately."""
        blk = self.mba.get_mblock(block_serial)
        if blk is None:
            logger.warning("Block %d not found", block_serial)
            return

        logger.debug(
            "Immediate zero state write: block %d, ea=%s", block_serial, hex(insn_ea)
        )
        if self._apply_zero_state_write(blk, insn_ea):
            self.modifications_applied += 1

    def queue_promote_operand_to_scalar(
        self,
        block_serial: int,
        host_ea: int,
        host_opcode: int,
        operand_side: str,
        description: str = "",
    ) -> None:
        """Promote a fused sub-instruction operand to a fresh kreg immediately."""
        if operand_side not in ("l", "r"):
            raise ValueError(f"operand_side must be 'l' or 'r', got {operand_side!r}")
        blk = self.mba.get_mblock(block_serial)
        if blk is None:
            logger.warning("Block %d not found", block_serial)
            return
        logger.debug(
            "Immediate promote_operand_to_scalar: block %d, host_ea=%s, side=%s",
            block_serial,
            hex(host_ea),
            operand_side,
        )
        if self._apply_promote_operand_to_scalar(
            blk,
            host_ea,
            host_opcode,
            operand_side,
        ):
            self.modifications_applied += 1

    def queue_create_and_redirect(
        self,
        source_block_serial: int,
        final_target_serial: int,
        instructions_to_copy: list | tuple,
        is_0_way: bool = False,
        expected_serial: int | None = None,
        description: str = "",
        old_target_serial: int | None = None,
    ) -> None:
        """Create an intermediate block and redirect immediately."""
        blk = self.mba.get_mblock(source_block_serial)
        if blk is None:
            logger.warning("Block %d not found", source_block_serial)
            return

        logger.debug(
            "Immediate create_and_redirect: %d -> (new) -> %d with %d instructions",
            source_block_serial,
            final_target_serial,
            len(instructions_to_copy),
        )
        if self._apply_create_and_redirect(
            blk,
            final_target_serial,
            instructions_to_copy,
            is_0_way,
            expected_serial=expected_serial,
            old_target_serial=old_target_serial,
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
            self.modifications_applied,
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
        # Keep this staged-atomic copy in lockstep with DeferredGraphModifier:
        # BLOCK_GOTO_CHANGE must never coerce a 2-way block into a goto.
        if blk.nsucc() != 1:
            logger.warning(
                "Block %d is not 1-way (nsucc=%d)",
                blk.serial,
                blk.nsucc(),
            )
            return False

        return change_1way_block_successor(blk, new_target, verify=False)

    def _apply_target_change(
        self,
        blk: ida_hexrays.mblock_t,
        new_target: int,
        old_target: int | None = None,
    ) -> bool:
        """Change a conditional jump's target."""
        if blk.tail is None:
            return False

        # Check if it's a conditional jump.
        if not _is_redirectable_conditional_tail(blk.tail):
            logger.warning("Block %d doesn't end with conditional jump", blk.serial)
            return False

        return change_2way_block_conditional_successor(
            blk,
            new_target,
            old_target=old_target,
            verify=False,
        )

    def _apply_convert_to_goto(
        self, blk: ida_hexrays.mblock_t, goto_target: int
    ) -> bool:
        """Connect a terminal block or collapse a 2-way block to a goto."""
        if blk.nsucc() == 0:
            return change_0way_block_successor(blk, goto_target, verify=False)
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
            "Instruction at EA %s not found in block %d", hex(insn_ea), blk.serial
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
            "Instruction at EA %s not found in block %d", hex(insn_ea), blk.serial
        )
        return False

    def _apply_zero_state_write(self, blk: ida_hexrays.mblock_t, insn_ea: int) -> bool:
        """Zero the source operand of a state variable write instruction.

        Finds ``m_mov #CONST, state_var`` at *insn_ea* and replaces ``#CONST``
        with ``#0``, keeping the instruction alive so the state variable is
        explicitly written to zero (killing entry-state liveness).
        """
        insn = blk.head
        while insn:
            if insn.ea == insn_ea:
                old_value = insn.l.nnn.value if insn.l.t == ida_hexrays.mop_n else 0
                insn.l.make_number(0, insn.l.size, insn.ea)
                logger.info(
                    "STATE_WRITE_ZERO: blk[%d]@0x%x — replaced state write "
                    "with m_mov #0 (was 0x%x)",
                    blk.serial,
                    insn_ea,
                    old_value,
                )
                return True
            insn = insn.next

        logger.warning(
            "Zero state write: instruction at EA %s not found in block %d",
            hex(insn_ea),
            blk.serial,
        )
        return False

    def _apply_promote_operand_to_scalar(
        self,
        blk: ida_hexrays.mblock_t,
        host_ea: int,
        host_opcode: int | None,
        operand_side: str | None,
    ) -> bool:
        """Promote a fused sub-instruction operand (mop_d) into its own
        standalone microcode instruction with a fresh kreg destination.

        See PromoteOperandToScalar dataclass for semantics. Recipe verified
        against hexrays.hpp by microcode-expert: kreg (not lvar), deep clone
        via copy ctor (not move), insert before host via insert_into_block
        with om=host.prev, prefer sub-insn EA, fallback to host EA.
        """
        if operand_side not in ("l", "r"):
            logger.warning(
                "promote_operand_to_scalar: invalid operand_side=%r at blk[%d]@0x%x",
                operand_side,
                blk.serial,
                host_ea,
            )
            return False

        host = blk.head
        prev = None
        while host is not None:
            if host.ea == host_ea and (
                host_opcode is None or host.opcode == host_opcode
            ):
                break
            prev = host
            host = host.next
        if host is None:
            logger.warning(
                "promote_operand_to_scalar: host insn at EA %s not found in block %d",
                hex(host_ea),
                blk.serial,
            )
            return False

        sub_mop = host.l if operand_side == "l" else host.r
        if sub_mop.t != ida_hexrays.mop_d or sub_mop.d is None:
            logger.warning(
                "promote_operand_to_scalar: blk[%d]@0x%x operand %s is not "
                "mop_d (t=%d) — nothing to promote",
                blk.serial,
                host_ea,
                operand_side,
                int(sub_mop.t),
            )
            return False

        sub_size = sub_mop.size
        sub_ea = sub_mop.d.ea
        if sub_ea == idaapi.BADADDR:
            sub_ea = host.ea

        kreg = self.mba.alloc_kreg(sub_size, True)
        if kreg == ida_hexrays.mr_none:
            logger.warning(
                "promote_operand_to_scalar: alloc_kreg(%d) returned mr_none "
                "at blk[%d]@0x%x",
                sub_size,
                blk.serial,
                host_ea,
            )
            return False

        # Deep clone via copy ctor — never move ownership of mop_d.d.
        promoted = ida_hexrays.minsn_t(sub_mop.d)
        promoted.ea = sub_ea
        promoted.d.erase()
        promoted.d.make_reg(kreg, sub_size)
        promoted.d.size = sub_size

        # insert_into_block(nm, om) inserts nm AFTER om; om=prev → before host.
        blk.insert_into_block(promoted, prev)

        # Replace the host's sub-operand with a register read of the kreg.
        sub_mop.make_reg(kreg, sub_size)

        # Re-seal use/def bookkeeping for the block.
        blk.mark_lists_dirty()

        logger.info(
            "PROMOTE_OPERAND_TO_SCALAR: blk[%d]@0x%x — hoisted operand "
            "%s (sub_ea=0x%x size=%d) into fresh kreg=%d",
            blk.serial,
            host_ea,
            operand_side,
            sub_ea,
            sub_size,
            kreg,
        )
        return True

    def _apply_create_and_redirect(
        self,
        source_blk: ida_hexrays.mblock_t,
        final_target: int,
        instructions_to_copy: list | tuple | None,
        is_0_way: bool,
        expected_serial: int | None,
        old_target_serial: int | None = None,
    ) -> bool:
        """
        Create a standalone intermediate block and redirect source through it.

        Creates: source_blk -> new_block -> final_target

        Uses :func:`create_standalone_block` instead of :func:`create_block`
        to avoid corrupting ``ref_block``'s CFG edges (INTERR 50856/50858).

        Supports both 1-way and 2-way source blocks. For 2-way sources,
        ``old_target_serial`` must equal ``source_blk.tail.d.b`` (the
        conditional/taken arm of the m_jcnd tail).
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

        nsucc = int(source_blk.nsucc())
        if nsucc not in (1, 2):
            logger.warning(
                "create_and_redirect: unsupported nsucc=%d for blk[%d]",
                nsucc,
                source_blk.serial,
            )
            return False

        # Pre-validate 2-way path BEFORE creating the new block so we never
        # leave an orphan when redirect cannot succeed.
        if nsucc == 2:
            if old_target_serial is None:
                logger.warning(
                    "create_and_redirect: 2-way source blk[%d] requires "
                    "old_target_serial to disambiguate arm",
                    source_blk.serial,
                )
                return False
            tail = source_blk.tail
            if tail is None or not ida_hexrays.is_mcode_jcond(int(tail.opcode)):
                tail_op = int(getattr(tail, "opcode", -1)) if tail is not None else -1
                logger.warning(
                    "create_and_redirect: 2-way source blk[%d] tail is not "
                    "a conditional jump (opcode=%d)",
                    source_blk.serial,
                    tail_op,
                )
                return False
            try:
                cond_target = int(tail.d.b)
            except Exception:
                logger.warning(
                    "create_and_redirect: 2-way source blk[%d] m_jcnd target "
                    "operand unreadable",
                    source_blk.serial,
                )
                return False
            if cond_target != int(old_target_serial):
                logger.warning(
                    "create_and_redirect: 2-way source blk[%d] conditional "
                    "arm targets blk[%d], expected old_target=%d (fallthrough "
                    "arm not supported)",
                    source_blk.serial,
                    cond_target,
                    int(old_target_serial),
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
        target_blk = (
            mba.get_mblock(final_target)
            if _is_live_block_serial(mba, final_target)
            else None
        )
        actual_is_0_way = is_0_way or (
            target_blk and target_blk.type == ida_hexrays.BLT_0WAY
        )

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
            if expected_serial is not None:
                self._begin_patch_block_creation(expected_serial)
            new_block = create_standalone_block(
                ref_block,
                instructions_to_copy,
                target_serial=None if actual_is_0_way else final_target,
                is_0_way=actual_is_0_way,
                verify=False,
            )
            if expected_serial is not None:
                self._bind_patch_block_creation(expected_serial, new_block.serial)
            if expected_serial is not None and new_block.serial != expected_serial:
                logger.info(
                    "create_and_redirect: drift expected blk[%d] -> realized blk[%d] "
                    "recorded in mutation gateway",
                    expected_serial,
                    new_block.serial,
                )
            new_stop_serial = mba.qty - 1
            for pred_serial in old_stop_pred_serials:
                pred_blk = mba.get_mblock(pred_serial)
                if pred_blk is None or pred_blk.serial == new_block.serial:
                    continue
                if pred_blk.nsucc() != 1 or pred_blk.succ(0) != new_block.serial:
                    continue
                if not change_1way_block_successor(
                    pred_blk, new_stop_serial, verify=False
                ):
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

            # Redirect source block to the new block. Dispatch on the
            # current source topology: 1-way uses change_1way; 2-way (with
            # validated m_jcnd conditional arm) uses change_2way.
            if nsucc == 1:
                redirect_ok = change_1way_block_successor(
                    source_blk, new_block.serial, verify=False
                )
            else:
                redirect_ok = change_2way_block_conditional_successor(
                    source_blk,
                    new_block.serial,
                    verify=False,
                    old_target=int(old_target_serial)
                    if old_target_serial is not None
                    else None,
                )
            if not redirect_ok:
                logger.warning(
                    "Failed to redirect block %d (nsucc=%d) to new block %d",
                    source_blk.serial,
                    nsucc,
                    new_block.serial,
                )
                return False

            logger.debug(
                "Created block %d: %d -> %d -> %d (source nsucc=%d)",
                new_block.serial,
                source_blk.serial,
                new_block.serial,
                final_target,
                nsucc,
            )
            return True

        except Exception as e:
            logger.error(
                "Exception in create_and_redirect for block %d: %s",
                source_blk.serial,
                e,
            )
            return False
