"""Backward resolution of microcode operands via CFG predecessor walks.

This module provides pure dataflow functions (no Z3) for resolving register
and stack-variable operands to their defining expressions by walking
single-predecessor chains in the IDA microcode CFG.

Public API:
    find_def_in_block          -- scan backward within one block for def
    resolve_mop_via_predecessors -- follow single-pred chains for def
    resolve_mop_to_ast         -- tracker-aware AST resolver
    resolve_memory_load_via_store -- resolve m_ldx to defining m_stx
    recursively_resolve_ast    -- recursive leaf resolution
"""

from __future__ import annotations

import os
import sys

import ida_hexrays

from d810.core import getLogger, typing
from d810.core.cymode import CythonMode
from d810.hexrays.expr.ast import AstLeaf, AstNode, get_mop_key
from d810.hexrays.ir.mop_snapshot import MopSnapshot
from d810.hexrays.ir.minsn_utils import minsn_to_ast
from d810.hexrays.ir.mop_utils import AstNodeBudget, mop_to_ast
from d810.hexrays.utils.hexrays_formatters import format_minsn_t, format_mop_t
from d810.hexrays.utils.hexrays_helpers import equal_mops_ignore_size

logger = getLogger(__name__)

# Feature flag: use native predecessor-walk def-search as primary resolution path.
# Set D810_PATTERN_USE_NATIVE_DEF_SEARCH=0 to disable and fall back to MopTracker only.
_USE_NATIVE_DEF_SEARCH = (
    os.environ.get("D810_PATTERN_USE_NATIVE_DEF_SEARCH", "1") != "0"
)

# Crash-safety budgets (ticket llr-pydd): a prior matcher attempt segfaulted IDA
# during PREOPT def-search via unbounded recursion / null deref. These hard caps
# bound the recursive resolver so it can never recurse infinitely or deref null,
# even on cyclic / degenerate microcode. The node budget is a per-call ceiling on
# the total number of leaf resolutions any single ``recursively_resolve_ast`` call
# may attempt (independent of the structural ``max_depth``).
_RESOLVE_NODE_BUDGET = 4096
# Hard upper bound on single-predecessor chain walks (defensive; the loop itself
# already caps at _MAX_PRED_DEPTH, this guards against a malformed CFG cycle).
_MAX_PRED_DEPTH = 8


def _valid_predecessor_search_budget(
    max_predecessor_blocks: int,
    max_paths: int,
) -> bool:
    """Return whether a caller-supplied predecessor search budget is valid."""

    return (
        type(max_predecessor_blocks) is int
        and 1 <= max_predecessor_blocks <= _MAX_PRED_DEPTH
        and type(max_paths) is int
        and 1 <= max_paths <= 32
    )

_SNAPSHOT_TYPES_REQUIRING_OWNED_MOP = {
    ida_hexrays.mop_d,
    ida_hexrays.mop_f,
    ida_hexrays.mop_a,
    ida_hexrays.mop_c,
    ida_hexrays.mop_p,
    ida_hexrays.mop_S,
    ida_hexrays.mop_l,
    ida_hexrays.mop_str,
}


def _microcode_instruction_identity(
    blk: ida_hexrays.mblock_t,
    ins: ida_hexrays.minsn_t,
) -> tuple[int, int]:
    """Return an exact, callback-local identity for a live microinstruction.

    An EA is only an origin anchor: multiple microinstructions in the same
    block (and even at the same maturity) can legitimately share it.  Prefer
    the underlying SWIG pointer so distinct Python wrappers for the same live
    instruction still compare equal, and fall back to Python object identity
    for test doubles or unusual bindings.  Callers must not retain this key
    beyond the current Hex-Rays callback.
    """

    try:
        block_serial = int(blk.serial)
    except (AttributeError, TypeError, ValueError):
        block_serial = -1
    try:
        instruction_pointer = int(ins.this)
    except (AttributeError, TypeError, ValueError):
        instruction_pointer = id(ins)
    return block_serial, instruction_pointer


def _materialize_mop_for_tracking(
    mop: ida_hexrays.mop_t | MopSnapshot,
    context: str,
    mba: ida_hexrays.mba_t | None = None,
) -> ida_hexrays.mop_t | None:
    """Return an owned ``mop_t`` suitable for IDA tracking APIs.

    AST leaves cache ``MopSnapshot`` values to avoid dangling borrowed
    references.  IDA APIs such as ``append_use_list`` and ``MopTracker`` still
    require a real SWIG ``mop_t``; passing a snapshot into ``ida_hexrays.mop_t``
    raises the ``new_mop_t`` overload error seen in debug logs.
    """
    if not isinstance(mop, MopSnapshot):
        return mop

    if (
        mop.t in _SNAPSHOT_TYPES_REQUIRING_OWNED_MOP
        and getattr(mop, "owned_mop", None) is None
        and not (
            mop.t == ida_hexrays.mop_S
            and getattr(mop, "stkoff", None) is not None
            and mba is not None
        )
    ):
        logger.debug(
            "%s: cannot materialize MopSnapshot type %s without owned_mop",
            context,
            mop.t,
        )
        return None

    try:
        materialized = mop.to_mop(mba=mba)
    except Exception as exc:
        logger.debug(
            "%s: failed to materialize MopSnapshot type %s: %s",
            context,
            mop.t,
            exc,
        )
        return None

    if materialized.t == ida_hexrays.mop_z and mop.t != ida_hexrays.mop_z:
        logger.debug(
            "%s: materialized empty mop_t for MopSnapshot type %s",
            context,
            mop.t,
        )
        return None

    return materialized


def _minsn_to_ast_with_budget(
    instruction: ida_hexrays.minsn_t,
    node_budget: AstNodeBudget | None,
) -> AstNode | AstLeaf | None:
    """Build a definition AST while preserving the legacy unbounded call path."""

    if node_budget is None:
        return minsn_to_ast(instruction)
    return minsn_to_ast(instruction, node_budget=node_budget)


def _mop_to_ast_with_budget(
    mop: ida_hexrays.mop_t,
    node_budget: AstNodeBudget | None,
) -> AstNode | AstLeaf | None:
    """Build a stored-value AST with the caller's optional occurrence budget."""

    if node_budget is None:
        return mop_to_ast(mop)
    return mop_to_ast(mop, node_budget=node_budget)


def _ast_width_bytes(ast: AstNode | AstLeaf | None) -> int | None:
    """Return an AST value width in bytes when its provenance is explicit.

    ``dest_size`` is the width of the value produced by an AST instruction,
    whereas a leaf's ``mop.size`` is the width at its use site.  Do not infer
    a missing width from a surrounding expression: partial-register
    definitions are precisely where that inference becomes unsound.
    """

    if ast is None:
        return None

    for candidate in (
        getattr(ast, "dest_size", None),
        getattr(getattr(ast, "mop", None), "size", None),
    ):
        if type(candidate) is int and candidate > 0:
            return candidate
    return None


def _truncate_ast_to_use_width(
    ast: AstNode | AstLeaf,
    use_width: int,
    node_budget: AstNodeBudget | None,
) -> AstNode:
    """Create a native low-part AST preserving a narrower use-site width."""

    if node_budget is not None:
        node_budget.consume()

    truncated = AstNode(ida_hexrays.m_low, ast, None)
    truncated.dest_size = use_width
    truncated.ea = getattr(ast, "ea", None)
    truncated.func_name = getattr(ast, "func_name", "")
    truncated.ins = getattr(ast, "ins", None)

    if node_budget is not None:
        node_budget.mark_charged(truncated)
    return truncated


# ---------------------------------------------------------------------------
# mlist helpers
# ---------------------------------------------------------------------------


def operand_to_mlist(
    blk: ida_hexrays.mblock_t, mop: ida_hexrays.mop_t
) -> ida_hexrays.mlist_t:
    """Build an ``mlist_t`` representing the locations touched by *mop*.

    Uses ``blk.append_use_list(ml, mop, MUST_ACCESS)``.

    Args:
        blk: The block context (needed for stack frame layout).
        mop: The operand to convert.

    Returns:
        An ``mlist_t`` with the locations of *mop*.
    """
    ml = ida_hexrays.mlist_t()
    blk.append_use_list(ml, mop, ida_hexrays.MUST_ACCESS)
    return ml


def instruction_uses(
    blk: ida_hexrays.mblock_t, ins: ida_hexrays.minsn_t
) -> ida_hexrays.mlist_t:
    """Return ``mlist_t`` of all locations read by *ins*.

    Uses ``blk.build_use_list(ins, MUST_ACCESS)``.

    Args:
        blk: The block containing *ins*.
        ins: The instruction to query.

    Returns:
        An ``mlist_t`` with all read locations.
    """
    return blk.build_use_list(ins, ida_hexrays.MUST_ACCESS)


def instruction_defs(
    blk: ida_hexrays.mblock_t, ins: ida_hexrays.minsn_t
) -> ida_hexrays.mlist_t:
    """Return ``mlist_t`` of all locations written by *ins*.

    Uses ``blk.build_def_list(ins, MUST_ACCESS)``.

    Args:
        blk: The block containing *ins*.
        ins: The instruction to query.

    Returns:
        An ``mlist_t`` with all written locations.
    """
    return blk.build_def_list(ins, ida_hexrays.MUST_ACCESS)


# ---------------------------------------------------------------------------
# Backward resolution
# ---------------------------------------------------------------------------


def resolve_memory_load_via_store(
    ldx_ins: ida_hexrays.minsn_t,
    blk: ida_hexrays.mblock_t,
    ins: ida_hexrays.minsn_t,
    *,
    node_budget: AstNodeBudget | None = None,
) -> AstNode | AstLeaf | None:
    """Resolve a memory load (m_ldx) to its defining store (m_stx).

    When we have an m_ldx instruction that loads from memory, we search backward
    to find the m_stx instruction that stored to the same memory location.

    Args:
        ldx_ins: The m_ldx instruction to resolve
        blk: The block containing the instruction
        ins: The instruction where the load is used

    Returns:
        The AST of the stored value, or None if not found
    """
    # m_ldx format: ldx result, segment, address
    # m_stx format: stx value, segment, address
    # We need to match the address operand (r) between load and store

    load_addr = ldx_ins.r  # Address being loaded from

    if load_addr is None:
        return None

    # Search backward through the block for a matching store
    cur_ins = ins.prev if ins else blk.tail

    while cur_ins is not None:
        if cur_ins.opcode == ida_hexrays.m_stx:
            # m_stx format: stx value, segment, address
            store_addr = cur_ins.r  # Address being stored to

            # Check if addresses match
            if store_addr is not None and load_addr is not None:
                # Simple equality check - compare address operands
                try:
                    addresses_match = equal_mops_ignore_size(load_addr, store_addr)
                except Exception as e:
                    logger.debug(
                        "resolve_memory_load_via_store: Error comparing mops: %s", e
                    )
                    addresses_match = False
                if addresses_match:
                    # Found matching store - return AST of stored value.  Keep
                    # AST construction outside the comparison guard so a
                    # caller's node-budget cutoff is never swallowed as a
                    # recoverable address-comparison failure.
                    # The stored value is in ldx_ins.l for stx.
                    stored_value = cur_ins.l
                    if stored_value is not None:
                        ast = _mop_to_ast_with_budget(stored_value, node_budget)
                        if ast is not None:
                            ast.ea = cur_ins.ea
                            ast.ins = cur_ins
                        if logger.debug_on:
                            logger.debug(
                                "resolve_memory_load_via_store: Resolved ldx to stx: %s -> %s",
                                format_minsn_t(ldx_ins),
                                format_minsn_t(cur_ins),
                            )
                        return ast

        cur_ins = cur_ins.prev

    logger.debug(
        "resolve_memory_load_via_store: No matching store found for %s",
        format_minsn_t(ldx_ins),
    )
    return None


def find_def_in_block(
    mop: ida_hexrays.mop_t | MopSnapshot,
    blk: ida_hexrays.mblock_t,
    before_ins: ida_hexrays.minsn_t | None,
) -> ida_hexrays.minsn_t | None:
    """Scan backward within a single block for the instruction defining *mop*.

    Args:
        mop: The register or stack-variable operand to find a definition for.
        blk: The block to search within.
        before_ins: Start scanning from the instruction *before* this one.
                    Pass None to start from the block tail.

    Returns:
        The most-recent instruction in the block that writes to *mop*, or None.
    """
    mop = _materialize_mop_for_tracking(
        mop,
        "find_def_in_block",
        mba=getattr(blk, "mba", None),
    )
    if mop is None:
        return None

    # Build the use-list for mop so we can test against instruction def-lists.
    ml = ida_hexrays.mlist_t()
    blk.append_use_list(ml, mop, ida_hexrays.MUST_ACCESS)
    if ml.empty():
        return None

    # Walk backwards from before_ins (or from the tail if before_ins is None).
    cur_ins = before_ins.prev if before_ins is not None else blk.tail
    while cur_ins is not None:
        def_ml = blk.build_def_list(
            cur_ins, ida_hexrays.MAY_ACCESS | ida_hexrays.FULL_XDSU
        )
        if ml.has_common(def_ml):
            return cur_ins
        cur_ins = cur_ins.prev
    return None


def resolve_mop_via_predecessors(
    mop: ida_hexrays.mop_t | MopSnapshot,
    blk: ida_hexrays.mblock_t,
    ins: ida_hexrays.minsn_t,
    *,
    max_predecessor_blocks: int = 1,
    max_paths: int = 1,
    node_budget: AstNodeBudget | None = None,
) -> AstNode | AstLeaf | None:
    """Resolve *mop* to an AST by following single-predecessor chains.

    Only follows predecessor blocks when there is exactly one predecessor,
    guaranteeing a single execution path from definition to use (path-sensitive
    by construction).  Tries the current block first as a fast path.

    Args:
        mop: The register or stack-variable mop to resolve.
        blk: The block containing *ins*.
        ins: The instruction at which *mop* is used.
        max_predecessor_blocks: Maximum number of single-predecessor blocks to
            inspect beyond the current block. Defaults to one.
        max_paths: Caller path budget. The native resolver follows one
            unambiguous path; broader path exploration remains owned by the
            MopTracker fallback.

    Returns:
        The AST of the defining instruction, or None if resolution failed.
    """
    if not _valid_predecessor_search_budget(
        max_predecessor_blocks,
        max_paths,
    ):
        return None
    if blk is None or mop is None:
        return None
    mop = _materialize_mop_for_tracking(
        mop,
        "resolve_mop_via_predecessors",
        mba=getattr(blk, "mba", None),
    )
    if mop is None:
        return None

    # Fast path: try the current block first.
    def_ins = find_def_in_block(mop, blk, ins)
    if def_ins is not None:
        ast = _minsn_to_ast_with_budget(def_ins, node_budget)
        if ast is not None:
            ast.ea = def_ins.ea
            ast.ins = def_ins
        if logger.debug_on:
            logger.debug(
                "resolve_mop_via_predecessors: resolved %s in current block via %s",
                format_mop_t(mop),
                format_minsn_t(def_ins),
            )
        return ast

    # Walk single-predecessor chain. Cycle detection (visited serials) guards
    # against a malformed CFG where the single-pred chain loops back on itself,
    # which would otherwise spin until the depth cap (crash-safety, llr-pydd).
    cur_blk = blk
    visited_serials: set[int] = set()
    for _ in range(max_predecessor_blocks):
        if cur_blk is None:
            return None
        try:
            cur_serial = int(cur_blk.serial)
        except Exception:
            return None
        if cur_serial in visited_serials:
            if logger.debug_on:
                logger.debug(
                    "resolve_mop_via_predecessors: cycle at block %d, stopping",
                    cur_serial,
                )
            return None
        visited_serials.add(cur_serial)
        # Bail out if there is not exactly one predecessor (ambiguous path).
        if cur_blk.npred() != 1:
            if logger.debug_on:
                logger.debug(
                    "resolve_mop_via_predecessors: %s has %d predecessors, stopping",
                    cur_blk.serial,
                    cur_blk.npred(),
                )
            return None

        pred_serial = cur_blk.pred(0)
        try:
            pred_blk = cur_blk.mba.get_mblock(pred_serial)
        except Exception as exc:
            logger.debug(
                "resolve_mop_via_predecessors: get_mblock(%d) failed: %s",
                pred_serial,
                exc,
            )
            return None

        # Search from the tail of the predecessor (no before_ins restriction).
        def_ins = find_def_in_block(mop, pred_blk, None)
        if def_ins is not None:
            ast = _minsn_to_ast_with_budget(def_ins, node_budget)
            if ast is not None:
                ast.ea = def_ins.ea
                ast.ins = def_ins
            if logger.debug_on:
                logger.debug(
                    "resolve_mop_via_predecessors: resolved %s in block %d via %s",
                    format_mop_t(mop),
                    pred_serial,
                    format_minsn_t(def_ins),
                )
            return ast

        cur_blk = pred_blk

    logger.debug(
        "resolve_mop_via_predecessors: depth limit reached for %s",
        format_mop_t(mop),
    )
    return None


def resolve_mop_to_ast(
    mop: ida_hexrays.mop_t | MopSnapshot,
    blk: ida_hexrays.mblock_t,
    ins: ida_hexrays.minsn_t,
    *,
    max_predecessor_blocks: int = 1,
    max_paths: int = 1,
    node_budget: AstNodeBudget | None = None,
) -> AstNode | AstLeaf | None:
    """Use MopTracker to find the instruction that defines mop, return its AST.

    This function is used to resolve register/stack variables to their defining
    expressions. For example, if we have:
        eax.4 = (x.4 * (x.4 - 1.4)) & 1.4
        setz eax.4, 0.4, cf.1

    When analyzing the setz instruction, eax.4 is just a register (mop_r), but
    by tracking backward we can find that it's actually the expression
    (x * (x-1)) & 1, which we can then prove is always 0.

    Also handles mop_d with m_ldx (memory loads). When we have:
        ADD(LDX(mem1), LDX(mem2))
    The loads read from memory locations. We track backward to find the stores
    that wrote to those locations and return the AST of the stored values.

    Args:
        mop: The mop_t to resolve (typically a register or stack variable,
             or mop_d with m_ldx for memory loads)
        blk: The block containing the instruction
        ins: The instruction where mop is used
        max_predecessor_blocks: MopTracker fallback block traversal budget.
            Defaults to one, preserving the existing local/cross-edge scope.
        max_paths: MopTracker fallback path budget. Defaults to one, so a
            caller never receives a definition from an ambiguous path unless
            it explicitly opts into broader exploration.

    Returns:
        The AST of the defining instruction's RHS, or None if not found
    """
    if not _valid_predecessor_search_budget(
        max_predecessor_blocks,
        max_paths,
    ):
        return None

    mop = _materialize_mop_for_tracking(
        mop,
        "resolve_mop_to_ast",
        mba=getattr(blk, "mba", None),
    )
    if mop is None:
        return None

    # Handle mop_d with m_ldx - resolve memory loads to their defining stores
    if mop.t == ida_hexrays.mop_d:
        nested = mop.d
        if nested is not None and nested.opcode == ida_hexrays.m_ldx:
            # m_ldx format: ldx result, segment, address
            # The destination (nested.d) is where the loaded value goes
            # We need to track that destination backwards to find its definition
            if nested.d is not None:
                dest_mop = nested.d
                # If the destination is a register or stack var, track it
                if dest_mop.t in (ida_hexrays.mop_r, ida_hexrays.mop_S):
                    # Recursively resolve using the destination
                    return resolve_mop_to_ast(
                        dest_mop,
                        blk,
                        ins,
                        max_predecessor_blocks=max_predecessor_blocks,
                        max_paths=max_paths,
                        node_budget=node_budget,
                    )
            # If we can't resolve via destination, try the address operand
            # to find a matching store (m_stx) instruction
            return resolve_memory_load_via_store(
                nested,
                blk,
                ins,
                node_budget=node_budget,
            )
        # For other mop_d types, no resolution possible
        return None

    # Only track register/stack variables - other types already have full AST info
    if mop.t not in (ida_hexrays.mop_r, ida_hexrays.mop_S):
        return None

    # PRIMARY: Native predecessor walk (path-sensitive).
    # Only follows single-predecessor chains -- guarantees one execution path
    # from definition to use, so no wrong definitions from CFF dispatchers.
    if _USE_NATIVE_DEF_SEARCH:
        result = resolve_mop_via_predecessors(
            mop,
            blk,
            ins,
            max_predecessor_blocks=max_predecessor_blocks,
            max_paths=max_paths,
            node_budget=node_budget,
        )
        if result is not None:
            return result

    # FALLBACK: MopTracker for multi-predecessor cases or early maturity.
    # Keep this lookup dynamic so hexrays does not hard-import evaluator layer.
    tracker_module = sys.modules.get("d810.evaluator.hexrays_microcode.tracker")
    if tracker_module is None:
        logger.debug("resolve_mop_to_ast: MopTracker module not loaded")
        return None
    MopTracker = getattr(tracker_module, "MopTracker", None)
    if MopTracker is None:
        logger.debug("resolve_mop_to_ast: MopTracker class not available")
        return None

    # Create tracker with an explicit caller-owned exploration budget. The
    # defaults retain the previous one-block/one-path behavior; wider traversal
    # remains an opt-in research tool rather than a global matcher policy.
    try:
        MopTracker.reset()  # Reset global path counter
        tracker = MopTracker(
            [mop],
            max_nb_block=max_predecessor_blocks,
            max_path=max_paths,
        )
        histories = tracker.search_backward(blk, ins)
    except Exception as e:
        logger.debug("resolve_mop_to_ast: Tracker failed: %s", e)
        return None

    if not histories:
        logger.debug("resolve_mop_to_ast: No history found for %s", format_mop_t(mop))
        return None

    # Get the first (and only) history
    history = histories[0]

    # Look for the *nearest* defining instruction in the history.
    # MopTracker stores instructions in chronological order inside each block
    # info, so iterate in reverse to pick the reaching definition closest to
    # the use site (ins) rather than an older overwritten definition.
    for blk_info in reversed(history.history):
        for def_ins in reversed(blk_info.ins_list):
            # Check if this instruction defines our mop
            # The defining instruction writes to our mop as its destination
            if def_ins.d is not None and def_ins.d.t == mop.t:
                # For registers, check if it's the same register
                if mop.t == ida_hexrays.mop_r and def_ins.d.r == mop.r:
                    # Build AST from the instruction's source operands
                    ast = _minsn_to_ast_with_budget(def_ins, node_budget)
                    if ast is not None:
                        ast.ea = def_ins.ea
                        ast.ins = def_ins
                    if logger.debug_on:
                        logger.debug(
                            "resolve_mop_to_ast: Resolved %s to %s from %s",
                            format_mop_t(mop),
                            ast,
                            format_minsn_t(def_ins),
                        )
                    return ast
                # For stack variables, compare the stack offset
                elif mop.t == ida_hexrays.mop_S:
                    try:
                        if def_ins.d.s.off == mop.s.off:
                            ast = _minsn_to_ast_with_budget(def_ins, node_budget)
                            if ast is not None:
                                ast.ea = def_ins.ea
                                ast.ins = def_ins
                            if logger.debug_on:
                                logger.debug(
                                    "resolve_mop_to_ast: Resolved %s to %s from %s",
                                    format_mop_t(mop),
                                    ast,
                                    format_minsn_t(def_ins),
                                )
                            return ast
                    except AttributeError:
                        pass

    logger.debug(
        "resolve_mop_to_ast: No defining instruction found for %s", format_mop_t(mop)
    )
    return None


def _py_slow_recursively_resolve_ast(
    ast: AstNode | AstLeaf | None,
    blk: ida_hexrays.mblock_t,
    ins: ida_hexrays.minsn_t,
    depth: int = 0,
    max_depth: int = 10,
    cache: dict | None = None,
    node_budget: AstNodeBudget | None = None,
) -> AstNode | AstLeaf | None:
    """Recursively resolve register/stack leaves in an AST to their defining expressions.

    This function handles multi-instruction expressions like:
        t1 = sub(x, 1)
        t2 = mul(t1, x)
        t3 = and(t2, 1)
        setz(t3, 0)

    Without recursive resolution, we'd only get `and(t2, 1)` where `t2` is still
    a register. With recursive resolution, we get the full expression:
        `and(mul(sub(x, 1), x), 1)` which Z3 can prove is always 0.

    Args:
        ast: The AST to resolve
        blk: Current block for backward search
        ins: Current instruction for backward search
        depth: Current recursion depth
        max_depth: Maximum recursion depth to prevent infinite loops
        cache: Optional dictionary for caching resolution results
        node_budget: Optional backend-neutral occurrence budget for replacement
            AST construction

    Returns:
        AST with register/stack leaves replaced by their defining expressions
    """
    if cache is None:
        cache = {}

    # Crash-safety: per-call node budget (independent of structural max_depth).
    # The resolver cap is threaded through the cache dict under a private key;
    # it remains independent from the optional proof-expansion budget. It
    # bounds total leaf-resolution attempts so a degenerate / cyclic def chain
    # cannot exhaust the stack (llr-pydd).
    budget = cache.get("__resolve_budget__")
    if budget is None:
        budget = [_RESOLVE_NODE_BUDGET]
        cache["__resolve_budget__"] = budget

    if depth >= max_depth:
        return ast

    if ast is None:
        return None

    if budget[0] <= 0:
        if logger.debug_on:
            logger.debug("recursively_resolve_ast: node budget exhausted, stopping")
        return ast

    # If it's a leaf with a register/stack mop or memory load, try to resolve it
    if ast.is_leaf():
        ast_leaf = typing.cast(AstLeaf, ast)
        if ast_leaf.mop is not None:
            # Check for resolvable mop types: registers, stack vars, or memory loads
            is_resolvable = ast_leaf.mop.t in (ida_hexrays.mop_r, ida_hexrays.mop_S)
            # Also check for mop_d with m_ldx (memory loads)
            if not is_resolvable and ast_leaf.mop.t == ida_hexrays.mop_d:
                nested = getattr(ast_leaf.mop, "d", None)
                if nested is not None and nested.opcode == ida_hexrays.m_ldx:
                    is_resolvable = True

            if is_resolvable and ins is not None:
                mop_key = get_mop_key(ast_leaf.mop)
                use_width = _ast_width_bytes(ast_leaf)
                cache_key = (
                    mop_key,
                    use_width,
                    _microcode_instruction_identity(blk, ins),
                )
                if cache_key in cache:
                    return cache[cache_key]

                # Charge the budget once per attempted leaf resolution.
                budget[0] -= 1
                resolved = resolve_mop_to_ast(
                    ast_leaf.mop,
                    blk,
                    ins,
                    node_budget=node_budget,
                )
                if resolved is not None and resolved is not ast:
                    resolved_width = _ast_width_bytes(resolved)
                    # A missing width is not permission to guess.  In
                    # particular, a narrow partial-register definition must
                    # never be widened into a full-register use.
                    if (
                        use_width is None
                        or resolved_width is None
                        or resolved_width < use_width
                    ):
                        cache[cache_key] = ast
                        return ast

                    # Update search context for children: search from the defining instruction
                    # This correctly handles register redefinitions within the same block.
                    new_ins = ins
                    if hasattr(resolved, "ins") and resolved.ins is not None:
                        new_ins = resolved.ins

                    # Recursively resolve the new AST
                    res = _py_slow_recursively_resolve_ast(
                        resolved,
                        blk,
                        new_ins,
                        depth + 1,
                        max_depth,
                        cache,
                        node_budget,
                    )
                    if resolved_width > use_width:
                        res = _truncate_ast_to_use_width(res, use_width, node_budget)
                    cache[cache_key] = res
                    return res
                cache[cache_key] = ast
        return ast

    # For non-leaf nodes, recursively resolve children
    ast_node = typing.cast(AstNode, ast)

    new_left = (
        _py_slow_recursively_resolve_ast(
            ast_node.left, blk, ins, depth, max_depth, cache, node_budget
        )
        if ast_node.left
        else None
    )
    new_right = (
        _py_slow_recursively_resolve_ast(
            ast_node.right, blk, ins, depth, max_depth, cache, node_budget
        )
        if ast_node.right
        else None
    )

    # If children changed, create new AST node
    if new_left is not ast_node.left or new_right is not ast_node.right:
        # Create a new AstNode with the same opcode but resolved children
        if node_budget is not None:
            node_budget.consume()
        new_ast = AstNode(ast_node.opcode, new_left, new_right)
        if node_budget is not None:
            node_budget.mark_charged(new_ast)
        new_ast.mop = ast_node.mop  # Preserve original mop info
        # Preserve destination metadata so downstream replacement can emit
        # a valid instruction destination instead of a transient value mop.
        new_ast.dst_mop = ast_node.dst_mop
        new_ast.dest_size = ast_node.dest_size
        new_ast.ea = ast_node.ea
        new_ast.func_name = ast_node.func_name
        if logger.debug_on:
            logger.debug(
                "recursively_resolve_ast: Rebuilt AST node: %s -> %s", ast_node, new_ast
            )
        return new_ast

    return ast


if CythonMode().is_enabled():
    try:
        from d810.speedups.evaluator.c_def_search import (
            recursively_resolve_ast as _compiled_recursively_resolve_ast,
        )

        _RECURSIVE_RESOLVER_BACKEND = "cython"
    except (ImportError, ModuleNotFoundError):
        _compiled_recursively_resolve_ast = None
        _RECURSIVE_RESOLVER_BACKEND = "python"
else:
    _compiled_recursively_resolve_ast = None
    _RECURSIVE_RESOLVER_BACKEND = "python"


def recursively_resolve_ast(
    ast: AstNode | AstLeaf | None,
    blk: ida_hexrays.mblock_t,
    ins: ida_hexrays.minsn_t,
    depth: int = 0,
    max_depth: int = 10,
    cache: dict | None = None,
    node_budget: AstNodeBudget | None = None,
) -> AstNode | AstLeaf | None:
    """Resolve AST definitions through the selected production backend."""

    if _compiled_recursively_resolve_ast is not None:
        return _compiled_recursively_resolve_ast(
            ast,
            blk,
            ins,
            depth,
            max_depth,
            cache,
            resolve_mop_to_ast,
            _microcode_instruction_identity,
            _RESOLVE_NODE_BUDGET,
            node_budget,
        )
    return _py_slow_recursively_resolve_ast(
        ast,
        blk,
        ins,
        depth=depth,
        max_depth=max_depth,
        cache=cache,
        node_budget=node_budget,
    )


def get_recursive_resolver_backend() -> str:
    """Return the selected recursive definition resolver for diagnostics."""

    return _RECURSIVE_RESOLVER_BACKEND
