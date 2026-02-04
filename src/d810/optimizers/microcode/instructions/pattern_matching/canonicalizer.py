"""
Canonicalization & Normalization logic for ASTs.

STATUS: NOT INTEGRATED - P4 (nice-to-have, not necessary)
========================================================

This module is NOT currently integrated into the pattern matching pipeline.
The existing O(N!) permutation approach (ast_generator) works well enough for
the current rule set where most patterns have 2-3 variables.

Handles AC-matching (Associative-Commutative) and structural normalization.

The canonicalization performs the following transforms:
1. Subtraction rewriting: sub(a, b) -> add(a, neg(b))
2. Negation sinking: neg(mul(x, 2)) -> mul(x, -2)
3. Double negation removal: neg(neg(x)) -> x
4. Operand sorting: For commutative ops, sort operands by hash for consistent ordering

FUNDAMENTAL LIMITATION: The Shadow Map Problem
==============================================

This canonicalization CANNOT be applied to INPUT ASTs (from real microcode) because
transformations create SYNTHETIC nodes that lose their connection to IDA microcode.

Example - in _negate_constant():

    new_const = AstConstant(f"neg_{node.name}", expected_value=-val)
    # ^^^ THIS IS THE PROBLEM - no mop reference!

The moment you transform sub(a, b) → add(a, neg(b)) or sink a negation into a
constant, you create synthetic nodes with no connection to the original IDA
microcode operands. Pattern matching requires mops to generate replacement
instructions via _copy_mops_from_ast() - without them, replacement fails.

WHY THIS IS HARD TO FIX
=======================

To preserve mop references through canonicalization, you'd need something like:

    class CanonicalNode:
        canonical_form: AstNode           # The transformed canonical AST
        original_node: AstNode            # Reference to original (for mop extraction)
        operand_mapping: dict[str, AstBase]  # Map canonical leaf names → original mops

This is essentially building:
1. A **term rewriting system** (like what compilers use)
2. A **two-way binding** between abstract algebra and concrete representation
3. **Provenance tracking** through transformations

This creeps into compiler frontend territory:
- SSA form has similar "where did this value come from" tracking
- LLVM's Value/Use chains
- GCC's tree-SSA infrastructure

CURRENT APPROACH: O(N!) Permutations
====================================

The ast_generator() function generates all permutations of commutative operands
for each pattern at startup. For a pattern like (x | y) - (x & y), it generates:
- (x | y) - (x & y)
- (y | x) - (x & y)
- (x | y) - (y & x)
- (y | x) - (y & x)
- ... and subtraction variants

This is O(N!) in the number of commutative operands, but:
- Most MBA rules have only 2-3 variables (manageable)
- The cost is paid once at startup
- Matching is still O(patterns × input_size)

POTENTIAL FUTURE OPTIMIZATIONS (if needed)
==========================================

Before implementing full canonicalization, consider:

1. **Measure first** - Profile startup time and matching time to see if this
   is actually a bottleneck. The current approach may be fast enough.

2. **Cache permutations** - Store generated permutations so we pay the cost
   once per session, not per function decompilation.

3. **Pattern-only canonicalization** - Canonicalize only the rule patterns,
   generate both canonical and non-canonical (subtraction) variants. Input
   matching would try multiple forms but preserve original mops.

4. **Lazy generation** - Generate permutations on-demand rather than all at startup.

Related: beads issue d810ng-d7j (P4)
"""
from __future__ import annotations

import hashlib
import typing

import ida_hexrays

from d810.expr.ast import AstBase, AstConstant, AstConstantProtocol, AstLeaf, AstNode

# Operations where order does not matter (Associative-Commutative ops)
COMMUTATIVE_OPS = {
    ida_hexrays.m_add,
    ida_hexrays.m_mul,
    ida_hexrays.m_and,
    ida_hexrays.m_or,
    ida_hexrays.m_xor,
    ida_hexrays.m_setz,
    ida_hexrays.m_setnz,
    ida_hexrays.m_cfadd,
    ida_hexrays.m_ofadd,
}


def get_ast_digest(node: AstBase | None) -> str:
    """
    Compute a structural hash for an AST node.

    This hash is used to sort operands of commutative operations
    to ensure consistent ordering (e.g., A+B == B+A).

    Args:
        node: The AST node to hash.

    Returns:
        A hex digest string representing the structure.
    """
    if node is None:
        return ""

    if not node.is_node():
        # For leaves/constants, hash their string representation
        return hashlib.md5(str(node).encode()).hexdigest()

    ast_node = typing.cast(AstNode, node)
    left_dig = get_ast_digest(ast_node.left) if ast_node.left else ""
    right_dig = get_ast_digest(ast_node.right) if ast_node.right else ""

    # Sort commutative operands by hash to ensure A+B == B+A
    if ast_node.opcode in COMMUTATIVE_OPS:
        if left_dig > right_dig:
            left_dig, right_dig = right_dig, left_dig

    sig = f"{ast_node.opcode}:{left_dig},{right_dig}"
    return hashlib.md5(sig.encode()).hexdigest()


def _is_numeric_constant(node: AstBase | None) -> bool:
    """Check if a node represents a numeric constant."""
    if node is None:
        return False
    # Use Protocol for hot-reload safety
    if isinstance(node, AstConstantProtocol):
        return node.expected_value is not None or (node.mop is not None and node.mop.t == ida_hexrays.mop_n)
    return False


def _get_constant_value(node: AstBase) -> int | None:
    """Get the numeric value of a constant node."""
    # Use Protocol for hot-reload safety
    if isinstance(node, AstConstantProtocol):
        if node.expected_value is not None:
            return node.expected_value
        if node.mop is not None and node.mop.t == ida_hexrays.mop_n:
            return node.mop.nnn.value
    return None


def _negate_constant(node: AstConstant) -> AstConstant:
    """Create a new constant with negated value."""
    val = _get_constant_value(node)
    if val is not None:
        # Create a new constant with negated expected_value
        new_const = AstConstant(f"neg_{node.name}", expected_value=-val)
        # Copy size if available
        if hasattr(node, 'expected_size') and node.expected_size is not None:
            new_const.expected_size = node.expected_size
        return new_const
    return node


def normalize_ast(node: AstBase | None) -> AstBase | None:
    """
    Structural normalization (bottom-up).

    Transforms:
    1. sub(a, b) -> add(a, neg(b))
    2. neg(mul(x, const)) -> mul(x, -const)  (sink negation into constant)
    3. neg(neg(x)) -> x  (remove double negation)

    Args:
        node: The AST node to normalize.

    Returns:
        The normalized AST node (may be the same node, modified in place).
    """
    if node is None:
        return None

    if not node.is_node():
        return node

    ast_node = typing.cast(AstNode, node)

    # 1. Recurse bottom-up (normalize children first)
    if ast_node.left:
        ast_node.left = normalize_ast(ast_node.left)
    if ast_node.right:
        ast_node.right = normalize_ast(ast_node.right)

    # 2. Rewrite subtraction: (A - B) -> (A + (-B))
    # This ensures rules like (x|y)-(x&y) match regardless of how IDA decompiled it
    if ast_node.opcode == ida_hexrays.m_sub:
        ast_node.opcode = ida_hexrays.m_add
        # Wrap right operand in negation
        ast_node.right = AstNode(ida_hexrays.m_neg, ast_node.right)
        # Recursively normalize the new neg node (might sink into constant)
        ast_node.right = normalize_ast(ast_node.right)

    # 3. Handle negation
    if ast_node.opcode == ida_hexrays.m_neg:
        child = ast_node.left

        # Case A: Double negation -> remove
        if child is not None and child.is_node():
            child_node = typing.cast(AstNode, child)
            if child_node.opcode == ida_hexrays.m_neg:
                # neg(neg(x)) -> x
                return child_node.left

        # Case B: Negation of multiplication with constant
        # neg(mul(x, 2)) -> mul(x, -2)
        # neg(mul(2, x)) -> mul(-2, x)
        if child is not None and child.is_node():
            child_node = typing.cast(AstNode, child)
            if child_node.opcode == ida_hexrays.m_mul:
                if _is_numeric_constant(child_node.left):
                    # Left operand is constant: neg(mul(const, x)) -> mul(-const, x)
                    child_node.left = _negate_constant(typing.cast(AstConstant, child_node.left))
                    return child_node
                elif _is_numeric_constant(child_node.right):
                    # Right operand is constant: neg(mul(x, const)) -> mul(x, -const)
                    child_node.right = _negate_constant(typing.cast(AstConstant, child_node.right))
                    return child_node

    return ast_node


def _sort_recursive(node: AstBase | None) -> AstBase | None:
    """
    Recursively sort operands of commutative operations.

    For operations like add, mul, and, or, xor, the operands are sorted
    by their structural hash to ensure consistent ordering.

    Args:
        node: The AST node to sort.

    Returns:
        The sorted AST node.
    """
    if node is None:
        return None

    if not node.is_node():
        return node

    ast_node = typing.cast(AstNode, node)

    # Recurse into children first
    if ast_node.left:
        ast_node.left = _sort_recursive(ast_node.left)
    if ast_node.right:
        ast_node.right = _sort_recursive(ast_node.right)

    # Sort operands of commutative operations
    if ast_node.opcode in COMMUTATIVE_OPS and ast_node.left and ast_node.right:
        left_dig = get_ast_digest(ast_node.left)
        right_dig = get_ast_digest(ast_node.right)

        if left_dig > right_dig:
            ast_node.left, ast_node.right = ast_node.right, ast_node.left

    return ast_node


def canonicalize_ast(node: AstBase | None) -> AstBase | None:
    """
    Master canonicalization function.

    Applies structural normalization followed by operand sorting to produce
    a canonical form for the AST. This ensures that mathematically equivalent
    expressions have the same canonical representation.

    Steps:
    1. Clone the input (to avoid mutating the original)
    2. Normalize structure (subtraction rewriting, negation sinking)
    3. Sort operands of commutative operations

    Args:
        node: The AST node to canonicalize.

    Returns:
        A new canonicalized AST node, or None if input was None.
    """
    if node is None:
        return None

    # Clone to avoid mutating the original
    # Note: We use clone() instead of copy.deepcopy() because AST nodes
    # may contain SWIG objects (mop_t, etc.) that cannot be pickled.
    cloned = node.clone()

    # Step 1: Normalize (fix structure, sink negations into constants)
    normalized = normalize_ast(cloned)

    # Step 2: Sort (enforce consistent operand ordering)
    return _sort_recursive(normalized)
