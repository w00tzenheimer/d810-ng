"""Operand/variable helpers with zero CFG coupling.

This module contains utility functions for working with microcode operands
(mop_t) and variable names. Split from cfg_utils.py as part of the
CFG Pass Pipeline refactor (Phase 1).
"""

from __future__ import annotations

import functools

import ida_hexrays

from d810.core import MOP_TO_AST_CACHE, getLogger
from d810.core.typing import Protocol
from d810.core.native_perf import register_provider as _register_native_perf_provider
from d810.hexrays.expr.ast import (
    AstBase,
    AstConstant,
    AstLeaf,
    AstNode,
    AstProxy,
    get_constant_mop,
    get_mop_key,
)
from d810.hexrays.ir.mop_snapshot import MopSnapshot
from d810.hexrays.ir.mop_ownership import mop_mba_owner_scope
from d810.hexrays.ir.number_operand import (
    MAX_MAKE_NUMBER_SIZE,
    VALID_MOP_SIZES,
    safe_make_number,
)
from d810.hexrays.utils.hexrays_formatters import (
    format_mop_t,
    mop_tree,
    mop_type_to_string,
    opcode_to_string,
    sanitize_ea,
)
from d810.hexrays.utils.hexrays_helpers import (
    MBA_RELATED_OPCODES,
    OPCODES_INFO,
    is_rotate_helper_call,
)

logger = getLogger(__name__)


class _NodeBudget(Protocol):
    """Structural protocol for the optional bounded AST-expansion budget."""

    def consume(self) -> None:
        ...

    def mark_charged(self, occurrence: object) -> None:
        ...

_VALID_MOP_SIZES = VALID_MOP_SIZES
_MAX_MAKE_NUMBER_SIZE = MAX_MAKE_NUMBER_SIZE


_NATIVE_PERF_ENABLED = False
_NATIVE_PERF_COUNTERS: dict[str, int] = {
    "builder_calls": 0,
    "local_cache_lookups": 0,
    "local_cache_hits": 0,
    "local_cache_misses": 0,
    "global_cache_lookups": 0,
    "global_cache_hits": 0,
    "global_cache_misses": 0,
    "owner_scope_key_calls": 0,
    "ast_constructions": 0,
    "proxy_returns": 0,
}


def _native_perf_configure(enabled: bool) -> None:
    global _NATIVE_PERF_ENABLED
    _NATIVE_PERF_ENABLED = bool(enabled)


def _native_perf_reset() -> None:
    for key in _NATIVE_PERF_COUNTERS:
        _NATIVE_PERF_COUNTERS[key] = 0


def _native_perf_snapshot() -> dict:
    return {
        "backend": "python",
        "counter_domain": "python-boundary",
        "provider_version": 1,
        "coverage": "minsn_utils -> mop_utils builder, local cache, global MOP_TO_AST_CACHE",
        "timing_model": "counts only; AST construction timing is not sampled",
        "counters": dict(_NATIVE_PERF_COUNTERS),
    }


def _native_perf_ast_constructed() -> None:
    if _NATIVE_PERF_ENABLED:
        _NATIVE_PERF_COUNTERS["ast_constructions"] += 1


def _mark_node_budget_charged(
    node_budget: _NodeBudget | None, occurrence: AstBase
) -> None:
    """Tell a compatible budget that *occurrence* was charged by the builder."""

    if node_budget is None:
        return
    marker = getattr(node_budget, "mark_charged", None)
    if marker is not None:
        marker(occurrence)


def _charge_cached_ast_occurrence(
    node_budget: _NodeBudget | None,
    occurrence: AstBase,
    *,
    root_already_consumed: bool = False,
) -> None:
    """Charge one logical occurrence of a cached AST subtree.

    A local builder-cache hit reuses the existing AST objects, but it still
    represents a complete recursive occurrence in the source mop tree. Walk
    only that reused subtree to charge each child occurrence and record the
    corresponding identities for the later visitor; no AST nodes are rebuilt.
    """

    if node_budget is None:
        return
    if not root_already_consumed:
        node_budget.consume()
    _mark_node_budget_charged(node_budget, occurrence)

    for child_name in ("left", "right", "dst"):
        child = getattr(occurrence, child_name, None)
        if child is not None:
            _charge_cached_ast_occurrence(node_budget, child)


def register_native_perf_provider() -> None:
    """Select the Python-boundary AST builder provider."""
    _register_native_perf_provider(
        "ast_builder",
        snapshot=_native_perf_snapshot,
        configure=_native_perf_configure,
        reset=_native_perf_reset,
    )


register_native_perf_provider()


class AstBuilderContext:
    """Manages the state during the recursive construction of an AST.

    This avoids passing multiple related arguments through the recursion
    and provides a clean way to store the lookup dictionary.
    """

    def __init__(self):
        # The list of unique AST nodes. The index in this list is the ast_index.
        self.unique_asts: list[AstBase] = []

        # The fast lookup dictionary.
        # Maps a mop's unique key to its index in the unique_asts list.
        self.mop_key_to_index: dict[tuple[int, str], int] = {}


def _mop_ast_cache_key(mop: object) -> tuple[object, tuple[int, ...]]:
    """Scope structural AST templates by embedded native MBA ownership."""
    if _NATIVE_PERF_ENABLED:
        _NATIVE_PERF_COUNTERS["owner_scope_key_calls"] += 1
    return get_mop_key(mop), mop_mba_owner_scope(mop)


# safe_make_number now lives in the leaf module d810.hexrays.ir.number_operand
# so the lowest-level helpers can use it without cycling back through here.
# Re-exported for the existing importers.


@functools.lru_cache(maxsize=1024)
def _get_mba_frame_size(mba: ida_hexrays.mba_t | None) -> int | None:
    """Return cached frame size for an MBA (fast C-level functools cache)."""
    if mba is None:
        return None
    for att in ("minstkref", "stacksize", "frsize", "fullsize"):
        val = getattr(mba, att, None)
        if val:
            return val
    return None


# Optional second-level cache: one name per SSA *valnum* (fast path)
_VALNUM_NAME_CACHE: dict[int, str] = {}


@functools.lru_cache(maxsize=16384)
def _cached_stack_var_name(
    mop_identity: int,  #  not used in the function but we need this bad boy for caching
    t: int,
    reg_or_off: int,
    size: int,
    valnum: int,
    frame_size: int | None,
) -> str:
    """Compute & cache printable variable names (identity-based)."""
    if t == ida_hexrays.mop_S:
        if frame_size is not None and frame_size >= reg_or_off:
            disp = frame_size - reg_or_off
            base = f"%var_{disp:X}.{size}"
        else:
            base = f"stk_{reg_or_off:X}.{size}"
    else:  # mop_r
        base = ida_hexrays.get_mreg_name(reg_or_off, size)
    return f"{base}{{{valnum}}}"


def get_stack_var_name(mop: ida_hexrays.mop_t) -> str | None:
    """Return a stable human-readable name for *mop*.

    Fast path: lookup by ``mop.valnum`` in `_VALNUM_NAME_CACHE`.  Falls back to
    identity-based LRU cache on a miss.
    """
    cached = _VALNUM_NAME_CACHE.get(mop.valnum)
    if cached is not None:
        return cached

    if mop.t == ida_hexrays.mop_S:
        frame_size = _get_mba_frame_size(getattr(mop.s, "mba", None))
        name = _cached_stack_var_name(
            id(mop), mop.t, mop.s.off, mop.size, mop.valnum, frame_size
        )
    elif mop.t == ida_hexrays.mop_r:
        name = _cached_stack_var_name(id(mop), mop.t, mop.r, mop.size, mop.valnum, None)
    else:
        return None
    return name


def constant_propagation_var_name(mop: ida_hexrays.mop_t) -> str | None:
    """Return the identity used by forward constant propagation.

    Hex-Rays can keep the same physical stack slot while assigning distinct SSA
    value numbers *and widths* to its definition and later use.  Constant
    propagation tracks storage, not SSA def-use chains, so a ``mop_S`` key
    deliberately omits both.  The consumer checks that a known value is at
    least as wide as the requested read before materializing it.  Registers
    retain their versioned names: collapsing those would let a constant cross
    an unrelated register write.
    """
    name = get_stack_var_name(mop)
    if name is None or mop.t != ida_hexrays.mop_S:
        return name
    base, separator, suffix = name.rpartition("{")
    if separator and suffix.endswith("}"):
        storage, dot, width = base.rpartition(".")
        if dot and width.isdecimal():
            return storage
        return base
    return name


def extract_base_and_offset(
    mop: ida_hexrays.mop_t,
) -> tuple[ida_hexrays.mop_t | None, int]:
    if (
        mop.t == ida_hexrays.mop_d
        and mop.d is not None
        and mop.d.opcode == ida_hexrays.m_add
    ):
        # (base + const)
        if mop.d.l and mop.d.l.t in {ida_hexrays.mop_S, ida_hexrays.mop_r}:
            off = mop.d.r.nnn.value if mop.d.r and mop.d.r.t == ida_hexrays.mop_n else 0
            return mop.d.l, off
        if mop.d.r and mop.d.r.t in {ida_hexrays.mop_S, ida_hexrays.mop_r}:
            off = mop.d.l.nnn.value if mop.d.l and mop.d.l.t == ida_hexrays.mop_n else 0
            return mop.d.r, off
    return None, 0


def mop_to_ast_internal(
    mop: ida_hexrays.mop_t,
    context: AstBuilderContext,
    root: bool = False,
    node_budget: _NodeBudget | None = None,
) -> AstBase | None:
    """Recursively convert a mop_t operand tree into an AST."""
    # Charge the occurrence before cache lookup, recursive descent, or AST
    # construction.  This is deliberately before deduplication: a repeated
    # operand occurrence is real work for a bounded proof even when the AST
    # builder can reuse a previously built template node.
    if node_budget is not None:
        node_budget.consume()
    if _NATIVE_PERF_ENABLED:
        _NATIVE_PERF_COUNTERS["builder_calls"] += 1
    # Only log at root
    if root and logger.debug_on:
        logger.debug(
            "[mop_to_ast_internal] Processing root mop: %s",
            str(mop.dstr()) if hasattr(mop, "dstr") else str(mop),
        )

    # Early filter at root: only process if supported, with one exception:
    # If the root is an m_call that has no argument list (r is mop_z) we treat it
    # as transparent and attempt to build an AST from its destination operand.
    if root:
        if hasattr(mop, "d") and hasattr(mop.d, "opcode"):
            root_opcode = mop.d.opcode

            # Transparent helper call wrappers are now normalised by a
            # peephole pass (TransparentCallUnwrapRule).  No special handling
            # needed here anymore.

            if root_opcode not in MBA_RELATED_OPCODES and not is_rotate_helper_call(
                mop.d
            ):
                if logger.debug_on:
                    logger.debug(
                        "Skipping AST build for unsupported root opcode: %s",
                        opcode_to_string(root_opcode),
                    )
                return None

    # 1. Create the unique, hashable key for the current mop.
    key = get_mop_key(mop)

    # 2. Thread-local deduplication: if we've already built an AST for *this*
    #    mop during the current recursive walk, return the existing instance to
    #    avoid exponential explosion.
    if _NATIVE_PERF_ENABLED:
        _NATIVE_PERF_COUNTERS["local_cache_lookups"] += 1
    if key in context.mop_key_to_index:
        if _NATIVE_PERF_ENABLED:
            _NATIVE_PERF_COUNTERS["local_cache_hits"] += 1
        existing_index = context.mop_key_to_index[key]
        existing = context.unique_asts[existing_index]
        _charge_cached_ast_occurrence(
            node_budget,
            existing,
            root_already_consumed=True,
        )
        return existing
    if _NATIVE_PERF_ENABLED:
        _NATIVE_PERF_COUNTERS["local_cache_misses"] += 1

    # Build AST nodes for rotate helper calls (__ROL*/__ROR*).
    # These are m_call instructions with an mop_h callee.  RotateHelperInlineRule
    # inlines them when both args are literals, but when the pipeline still sees
    # them (e.g. Z3ConstantOptimization at an earlier maturity) we need to build
    # a proper AstNode so that evaluate() can compute the result.
    if (
        mop.t == ida_hexrays.mop_d
        and mop.d is not None
        and is_rotate_helper_call(mop.d)
    ):
        call_ins = mop.d  # the inner m_call minsn_t

        # Extract helper name from the callee operand (ins.l is mop_h)
        helper_name: str = ""
        if call_ins.l is not None and call_ins.l.t == ida_hexrays.mop_h:
            helper_name = (call_ins.l.helper or "").lstrip("!")

        if helper_name:
            # Determine argument mops.  Hex-Rays uses two layouts:
            #   Pattern A: args packed in mop_f stored in call_ins.r
            #   Pattern B/C: value in call_ins.r, shift in call_ins.d (compact)
            val_mop: ida_hexrays.mop_t | None = None
            rot_mop: ida_hexrays.mop_t | None = None

            if (
                call_ins.r is not None
                and call_ins.r.t == ida_hexrays.mop_f
                and hasattr(call_ins.r, "f")
                and call_ins.r.f is not None
                and len(call_ins.r.f.args) >= 2
            ):
                val_mop = call_ins.r.f.args[0]
                rot_mop = call_ins.r.f.args[1]
            elif (
                call_ins.d is not None
                and call_ins.d.t == ida_hexrays.mop_f
                and hasattr(call_ins.d, "f")
                and call_ins.d.f is not None
                and len(call_ins.d.f.args) >= 2
            ):
                val_mop = call_ins.d.f.args[0]
                rot_mop = call_ins.d.f.args[1]
            elif call_ins.r is not None and call_ins.d is not None:
                val_mop = call_ins.r
                rot_mop = call_ins.d

            if val_mop is not None and rot_mop is not None:
                left_ast = mop_to_ast_internal(
                    val_mop, context, node_budget=node_budget
                )
                right_ast = mop_to_ast_internal(
                    rot_mop, context, node_budget=node_budget
                )

                if left_ast is not None and right_ast is not None:
                    tree = AstNode(ida_hexrays.m_call, left_ast, right_ast)
                    _native_perf_ast_constructed()
                    tree.func_name = helper_name

                    if hasattr(mop, "size") and mop.size:
                        tree.dest_size = mop.size
                    elif hasattr(call_ins, "size") and call_ins.size:
                        tree.dest_size = call_ins.size
                    else:
                        tree.dest_size = None

                    tree.mop = MopSnapshot.from_mop(mop)
                    tree.ea = sanitize_ea(call_ins.ea)

                    if logger.debug_on:
                        logger.debug(
                            "[mop_to_ast_internal] Created AstNode for rotate helper %s (ea=0x%X): %s",
                            helper_name,
                            call_ins.ea if hasattr(call_ins, "ea") else -1,
                            tree,
                        )

                    new_index = len(context.unique_asts)
                    tree.ast_index = new_index
                    context.unique_asts.append(tree)
                    context.mop_key_to_index[key] = new_index
                    _mark_node_budget_charged(node_budget, tree)
                    return tree

    # Helper calls that evaluate to constants are now canonicalised by
    # ConstantCallResultFoldRule (peephole GLBOPT1).

    # NEW: Build AST nodes for MBA-related opcodes (binary or unary)
    if mop.t == ida_hexrays.mop_d and mop.d.opcode in MBA_RELATED_OPCODES:
        nb_ops = OPCODES_INFO[mop.d.opcode]["nb_operands"]

        # Gather children ASTs based on operand count
        left_ast = (
            mop_to_ast_internal(mop.d.l, context, node_budget=node_budget)
            if mop.d.l is not None
            else None
        )
        right_ast = (
            mop_to_ast_internal(mop.d.r, context, node_budget=node_budget)
            if (nb_ops >= 2 and mop.d.r is not None)
            else None
        )

        # Require at least the mandatory operands; if missing, fall back to leaf
        if left_ast is None:
            # Can't build meaningful node - fallback later to leaf
            if logger.debug_on:
                logger.debug(
                    "[mop_to_ast_internal] Missing mandatory operand(s) for opcode %s, will treat as leaf",
                    opcode_to_string(mop.d.opcode),
                )
        else:
            # Only use dst_ast if destination present (ternary ops like m_stx etc.)
            dst_ast = (
                mop_to_ast_internal(
                    mop.d.d, context, node_budget=node_budget
                )
                if mop.d.d is not None
                else None
            )
            tree = AstNode(mop.d.opcode, left_ast, right_ast, dst_ast)
            _native_perf_ast_constructed()

            # Set dest_size robustly
            if hasattr(mop, "size") and mop.size:
                tree.dest_size = mop.size
            elif hasattr(mop.d, "size") and mop.d.size:
                tree.dest_size = mop.d.size
            elif mop.d.l is not None and hasattr(mop.d.l, "size"):
                tree.dest_size = mop.d.l.size
            else:
                tree.dest_size = None

            tree.mop = MopSnapshot.from_mop(mop)
            tree.ea = sanitize_ea(mop.d.ea)

            if logger.debug_on:
                logger.debug(
                    "[mop_to_ast_internal] Created AstNode for opcode %s (ea=0x%X): %s",
                    opcode_to_string(mop.d.opcode),
                    mop.d.ea if hasattr(mop.d, "ea") else -1,
                    tree,
                )
            new_index = len(context.unique_asts)
            tree.ast_index = new_index
            context.unique_asts.append(tree)
            context.mop_key_to_index[key] = new_index
            _mark_node_budget_charged(node_budget, tree)
            return tree

    # Special handling for mop_d that wraps an m_ldc as a constant leaf
    if (
        mop.t == ida_hexrays.mop_d
        and mop.d is not None
        and mop.d.opcode == ida_hexrays.m_ldc
    ):
        # Only treat it as constant if the *source* of the ldc is itself a
        # numeric constant.  Otherwise we ignore the ldc wrapper and fall
        # back to the generic leaf logic below.
        ldc_src = mop.d.l
        if ldc_src is not None and ldc_src.t == ida_hexrays.mop_n:
            const_val = int(ldc_src.nnn.value)
            const_size = ldc_src.size
            if node_budget is not None:
                node_budget.consume()

            const_leaf = AstConstant(hex(const_val), const_val, const_size)
            _native_perf_ast_constructed()
            # Clone numeric mop to detach from Hex-Rays internal storage
            cloned_mop = ida_hexrays.mop_t()
            safe_make_number(cloned_mop, const_val, const_size)
            const_leaf.mop = cloned_mop
            const_leaf.dest_size = const_size

            new_index = len(context.unique_asts)
            const_leaf.ast_index = new_index
            context.unique_asts.append(const_leaf)
            context.mop_key_to_index[key] = new_index
            _mark_node_budget_charged(node_budget, const_leaf)
            return const_leaf

    # Fallback for any unhandled mop: treat as a leaf.
    # This is for simple operands (registers, stack vars) or complex
    # instructions that are not part of our MBA analysis.
    if (
        mop.t != ida_hexrays.mop_d
        or (mop.d.opcode not in MBA_RELATED_OPCODES)
        or mop.d.l is None
        or mop.d.r is None
    ):
        tree: AstBase | None
        if mop.t == ida_hexrays.mop_n:
            const_val = int(mop.nnn.value)
            const_size = mop.size
            tree = AstConstant(hex(const_val), const_val, const_size)
            _native_perf_ast_constructed()
            # Re-use a shared constant mop_t from the global cache to avoid the
            # overhead of allocating a fresh object for every identical literal.
            tree.mop = get_constant_mop(const_val, const_size)
            tree.dest_size = const_size  # detached copy
        # Typed-immediate wrappers (mop_f) are now normalised by the
        # TypedImmediateCanonicaliseRule peephole pass.  If we still see one
        # here it means it holds *no* literal value, therefore fall through to
        # generic leaf creation.
        elif mop.t == ida_hexrays.mop_f:
            tree = None
        else:
            tree = None

        # ------------------------------------------------------------------
        # If we still haven't built a node, create a generic AstLeaf now.  This
        # guarantees that *tree* is always defined even if new mop_t kinds are
        # introduced in future IDA versions.
        # ------------------------------------------------------------------
        if tree is None:
            tree = AstLeaf(format_mop_t(mop))
            _native_perf_ast_constructed()
            if logger.debug_on:
                logger.debug(
                    "[mop_to_ast_internal] Tree is NONE! Defaulting to AstLeaf for mop type %s dstr=%s",
                    mop_type_to_string(mop.t),
                    str(mop.dstr()) if hasattr(mop, "dstr") else str(mop),
                )
            tree.dest_size = mop.size

        # Store MopSnapshot instead of borrowed mop_t to prevent use-after-free.
        # For constants, we've already stored a cached mop_t from get_constant_mop().
        # For non-constants, store a snapshot that create_mop() can reconstruct.
        if tree.is_constant():
            # Preserve previously assigned cached constant mop (from get_constant_mop)
            tree.mop = getattr(tree, "mop", None) or get_constant_mop(
                tree.value, mop.size
            )
        else:
            # Non-constant leaf: store snapshot instead of borrowed reference
            tree = AstLeaf(format_mop_t(mop))
            _native_perf_ast_constructed()
            if logger.debug_on:
                logger.debug(
                    "[mop_to_ast_internal] Fallback to AstLeaf for mop type %s dstr=%s",
                    mop_type_to_string(mop.t),
                    str(mop.dstr()) if hasattr(mop, "dstr") else str(mop),
                )
            tree.dest_size = mop.size
            tree.mop = MopSnapshot.from_mop(mop)
        dest_size = (
            mop.size
            if mop.t != ida_hexrays.mop_d
            else mop.d.d.size
            if mop.d.d is not None
            else mop.size
        )
        tree.dest_size = dest_size
        new_index = len(context.unique_asts)
        tree.ast_index = new_index
        context.unique_asts.append(tree)
        context.mop_key_to_index[key] = new_index
        _mark_node_budget_charged(node_budget, tree)
        return tree

    # If we reach here, we failed to build an AST. Log the full mop tree.
    logger.error("[mop_to_ast_internal] Could not build AST for mop. Dumping mop tree:")
    mop_tree(mop)
    return None


def mop_to_ast(
    mop: ida_hexrays.mop_t, *, node_budget: _NodeBudget | None = None
) -> AstProxy | None:
    """Convert a mop_t to an AST node, with caching to avoid re-computation.

    Returns a deep copy of the cached AST to prevent side-effects from
    mutations by the caller.
    """

    # A bounded proof must account for the real recursive builder, not a
    # post-construction AST counter or a parallel approximation.  Bypass the
    # global template cache for this path so every occurrence reaches
    # ``mop_to_ast_internal`` and consumes its budget before descent or
    # construction.  The bounded path is intentionally isolated from the
    # ordinary cache because a cached template would skip that recursion.
    if node_budget is not None:
        builder_context = AstBuilderContext()
        mop_ast = mop_to_ast_internal(
            mop, builder_context, root=True, node_budget=node_budget
        )
        if not mop_ast:
            return None
        mop_ast.compute_sub_ast()
        mop_ast.freeze()
        return AstProxy(mop_ast)

    # 1. Create a stable, hashable key from the mop_t object.
    cache_key = _mop_ast_cache_key(mop)

    # 2. Global template cache: return a proxy if we already know the template
    if _NATIVE_PERF_ENABLED:
        _NATIVE_PERF_COUNTERS["global_cache_lookups"] += 1
    found, cached_template = MOP_TO_AST_CACHE.lookup(cache_key)
    if found:
        if _NATIVE_PERF_ENABLED:
            _NATIVE_PERF_COUNTERS["global_cache_hits"] += 1
        if cached_template is None:
            return None  # Previously determined unconvertible.
        if _NATIVE_PERF_ENABLED:
            _NATIVE_PERF_COUNTERS["proxy_returns"] += 1
        return AstProxy(cached_template)
    if _NATIVE_PERF_ENABLED:
        _NATIVE_PERF_COUNTERS["global_cache_misses"] += 1

    builder_context = AstBuilderContext()
    # Start the optimized recursive build.

    if not (mop_ast := mop_to_ast_internal(mop, builder_context, root=True)):
        # Cache the failure to avoid re-computing it.
        MOP_TO_AST_CACHE[cache_key] = None
        return None

    # This mutates the mop_ast object, populating its sub_ast_info.
    # We do this ONCE before caching the "template" object, then we
    # freeze the object to prevent mutations.
    mop_ast.compute_sub_ast()
    mop_ast.freeze()

    # 4. Store the newly computed "template" object in the cache.
    MOP_TO_AST_CACHE[cache_key] = mop_ast

    # 5. Return a proxy to the caller for safety.
    if _NATIVE_PERF_ENABLED:
        _NATIVE_PERF_COUNTERS["proxy_returns"] += 1
    return AstProxy(mop_ast)


__all__ = [
    "safe_make_number",
    "get_stack_var_name",
    "constant_propagation_var_name",
    "extract_base_and_offset",
    "mop_to_ast",
    "mop_to_ast_internal",
    "AstBuilderContext",
    "_VALID_MOP_SIZES",
    "_get_mba_frame_size",
    "_cached_stack_var_name",
    "_VALNUM_NAME_CACHE",
]
