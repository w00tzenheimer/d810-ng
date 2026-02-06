"""
This module replaces the original pattern matching optimizer with a
canonicalisation and egraph‑style matcher.  The original implementation
generated a potentially enormous number of fuzzy pattern permutations in
order to handle commutative and associative operations.  This new
implementation avoids that combinatorial explosion by canonicalising
both the pattern and the candidate microcode AST before matching them.

The canonicalisation step flattens and sorts operands of commutative
and associative operators (addition, multiplication, bitwise‐or, bitwise‐and
and bitwise‐xor).  Subtraction is rewritten into addition of a negated
operand.  Negation is simplified where possible.  Once canonicalised
both the pattern and the candidate instruction have a unique shape
regardless of operand ordering, allowing a single match to succeed
instead of having to enumerate all permutations.

When a rule matches, we construct a fresh AST in the shape of the
original pattern and populate it with the matched operands.  We then
delegate to the existing rule logic to copy microcode (mops), perform
additional candidate checks and build the replacement instruction.

This approach is analogous to equality saturation (egraphs) in that
equivalent trees collapse to a canonical representation.  It yields
dramatically fewer pattern candidates to consider and therefore avoids
the exponential blow‑up of the previous scheme.
"""

from __future__ import annotations

import copy
import dataclasses
import typing

import ida_hexrays  # noqa: F401,F403

from d810.core import getLogger
from d810.expr.ast import (
    AstBase,
    AstConstant,
    AstConstantProtocol,
    AstLeaf,
    AstLeafProtocol,
    AstNode,
    AstNodeProtocol,
    minsn_to_ast,
)
from d810.hexrays.hexrays_formatters import format_minsn_t

# Additional helpers for some rules.  These functions and tables are
# imported from the original helpers module.  They are used in the
# candidate checks below.  If these symbols are not available at
# runtime, importing them will raise which allows the caller to see
# that the helpers are missing.
from d810.hexrays.hexrays_helpers import (
    AND_TABLE,
    equal_bnot_mop,
    equal_mops_ignore_size,
)
from d810.optimizers.microcode.instructions.handler import (
    GenericPatternRule,
    InstructionOptimizer,
)

if typing.TYPE_CHECKING:
    from d810.core import OptimizationStatistics

# Reuse the same loggers as the original implementation.
optimizer_logger = getLogger("D810.optimizer")
pattern_search_logger = getLogger("D810.pattern_search")


COMMUTATIVE_OPCODES = {
    ida_hexrays.m_add,
    ida_hexrays.m_mul,
    ida_hexrays.m_or,
    ida_hexrays.m_and,
    ida_hexrays.m_xor,
}


def _flatten_operands(node: AstNode, opcode: int) -> list[AstBase]:
    """Recursively collect all operands of a commutative/associative operator.

    If the node's opcode matches the operator, its children are
    flattened into a single list.  Otherwise the node itself is
    returned as the sole element.  Leaves and constants are returned
    unchanged.

    Args:
        node: The AST node to flatten.
        opcode: The opcode of the operator being flattened.
    Returns:
        A list of operand ASTs.
    """
    if not isinstance(node, AstBase) or not node.is_node():
        return [node]
    node = typing.cast(AstNode, node)
    if node.opcode != opcode:
        return [node]
    # recurse into children collecting operands of the same opcode
    operands: list[AstBase] = []
    if node.left is not None:
        operands += _flatten_operands(node.left, opcode)
    if node.right is not None:
        operands += _flatten_operands(node.right, opcode)
    return operands


def _build_balanced_tree(opcode: int, operands: list[AstBase]) -> AstBase:
    """Reconstruct a binary tree from a list of operands.

    Given a list of operands and an opcode, this helper builds
    a left‑associative binary tree.  The ordering of the operands
    should already be normalised (e.g. sorted) by the caller.

    Args:
        opcode: The opcode for the internal nodes.
        operands: A list of operands after flattening and sorting.
    Returns:
        An AST with the operands combined using the given opcode.
    """
    assert len(operands) > 0
    if len(operands) == 1:
        return operands[0]
    cur: AstBase = operands[0]
    for operand in operands[1:]:
        # Ensure both sides are AstBase when constructing an AstNode
        left = typing.cast(AstBase, cur)
        right = typing.cast(AstBase, operand)
        cur = AstNode(opcode, left, right)
    return cur


def canonicalize_ast(node: AstBase | None) -> AstBase | None:
    """Return a canonicalised copy of the given AST.

    The canonicalisation performs the following transforms:
    * For addition, multiplication, bitwise or, bitwise and and bitwise xor,
      all nested occurrences of the operator are flattened into a list of
      operands, each operand is canonicalised recursively, the list is sorted
      by the textual pattern of each operand and finally rebuilt into a
      left‑associative binary tree.
    * Subtraction is rewritten into addition of the left operand and the
      negation of the right operand.  This allows x − y to be matched
      against x + (−y) regardless of which representation appears in the
      candidate.
    * Negation of a negation collapses: −(−x) becomes x.
    * All other nodes are canonicalised recursively on their children.

    Leaves (AstLeaf) and constants (AstConstant) are returned unchanged.

    Args:
        node: The AST to canonicalise.
    Returns:
        A new canonicalised AST or None if the input was None.
    """
    if node is None:
        return None
    # For leaves and constants we simply return a shallow copy to avoid
    # mutating the original AST.  AstLeaf and AstConstant inherit from
    # AstBase but are not nodes (is_node() returns False) so they
    # bypass the canonicalisation rules below.
    if not node.is_node():
        return copy.deepcopy(node)
    # Work with a deep copy of the node to avoid mutating the original
    ast = typing.cast(AstNode, copy.deepcopy(node))
    opcode = ast.opcode
    # Handle commutative and associative operators
    if opcode in COMMUTATIVE_OPCODES:
        # Flatten nested operators and canonicalise all operands
        operands: list[AstBase] = []
        for op in _flatten_operands(ast, opcode):
            operands.append(canonicalize_ast(op))
        # Sort operands by their textual pattern to produce a deterministic
        # ordering.  get_pattern() returns a pattern string identifying
        # the shape of the subexpression; it is safe to use for sorting.
        operands.sort(
            key=lambda n: (n.get_pattern() if hasattr(n, "get_pattern") else str(n))
        )
        return _build_balanced_tree(opcode, operands)
    # Rewrite subtraction into addition of a negated operand
    if opcode == ida_hexrays.m_sub:
        # canonicalise children first
        left = canonicalize_ast(ast.left) if ast.left is not None else None
        right = canonicalize_ast(ast.right) if ast.right is not None else None
        # Convert x - y into x + (-y)
        neg_right: AstBase
        if (
            isinstance(right, AstBase)
            and right.is_node()
            and typing.cast(AstNode, right).opcode == ida_hexrays.m_neg
        ):
            # -(y) negated again becomes y
            inner = typing.cast(AstNode, right)
            neg_right = canonicalize_ast(inner.left)
        else:
            neg_right = AstNode(ida_hexrays.m_neg, right)
        # Recursively canonicalise the resulting addition
        return canonicalize_ast(AstNode(ida_hexrays.m_add, left, neg_right))
    # Simplify double negation
    if opcode == ida_hexrays.m_neg:
        sub = canonicalize_ast(ast.left) if ast.left is not None else None
        # If the child is itself a negation, collapse them
        if (
            isinstance(sub, AstBase)
            and sub.is_node()
            and typing.cast(AstNode, sub).opcode == ida_hexrays.m_neg
        ):
            inner = typing.cast(AstNode, sub)
            return canonicalize_ast(inner.left)
        return AstNode(ida_hexrays.m_neg, sub)
    # Default case: recursively canonicalise left and right children
    left = canonicalize_ast(ast.left) if ast.left is not None else None
    right = canonicalize_ast(ast.right) if ast.right is not None else None
    return AstNode(opcode, left, right)


def _ast_equal(a: AstBase, b: AstBase) -> bool:
    """Return True if two ASTs have the same pattern.

    This helper compares two ASTs using their pattern strings if
    available; otherwise it falls back to structural equality via
    `get_pattern()`.  This is used to ensure consistency when
    matching variables that may appear multiple times in a pattern.
    """
    # Leaves and constants implement get_pattern() as part of AstBase
    if hasattr(a, "get_pattern") and hasattr(b, "get_pattern"):
        return a.get_pattern() == b.get_pattern()
    # Fallback structural comparison
    return str(a) == str(b)


def match_pattern(
    pattern: AstBase | None, candidate: AstBase | None, mapping: dict[str, AstBase]
) -> bool:
    """Attempt to match a canonicalised pattern against a canonicalised candidate.

    The matching algorithm walks both trees simultaneously.  When a
    pattern leaf (AstLeaf) is encountered, the corresponding candidate
    subtree is recorded in the mapping.  Subsequent uses of the same
    pattern variable must match identically.  Pattern constants
    (AstConstant) with a `None` value are treated as variables and are
    similarly recorded; constants with a concrete value must match
    exactly against constants in the candidate.

    For commutative/associative operations the canonicaliser has
    already sorted and flattened operands, so simple left/right
    matching suffices.

    Args:
        pattern: The canonicalised pattern AST.
        candidate: The canonicalised candidate AST.
        mapping: A dict recording assignments of pattern variables to
          candidate subtrees.  This dict is updated in place.
    Returns:
        True if the pattern matches the candidate, False otherwise.
    """
    # Both None: match
    if pattern is None and candidate is None:
        return True
    # One is None and the other is not: mismatch
    if pattern is None or candidate is None:
        return False
    # Pattern leaf: bind variable (use Protocol for hot-reload safety)
    if isinstance(pattern, AstLeafProtocol):
        var_name = pattern.name
        if var_name in mapping:
            return _ast_equal(mapping[var_name], candidate)
        # Record the first occurrence of this variable
        mapping[var_name] = candidate
        return True
    # Pattern constant: capture or literal (use Protocol for hot-reload safety)
    if isinstance(pattern, AstConstantProtocol):
        if pattern.value is None:
            # Capturing constant variable
            var_name = pattern.name
            if var_name in mapping:
                # Ensure the previously bound constant matches the current candidate
                bound = mapping[var_name]
                # Both must be constants and have the same value
                return (
                    isinstance(bound, AstConstantProtocol)
                    and isinstance(candidate, AstConstantProtocol)
                    and bound.value == typing.cast(AstConstant, candidate).value
                )
            if not isinstance(candidate, AstConstantProtocol):
                return False
            mapping[var_name] = candidate
            return True
        # Literal constant: require exact match of the numeric value
        if not isinstance(candidate, AstConstantProtocol):
            return False
        return pattern.value == typing.cast(AstConstant, candidate).value
    # Pattern is an AST node: candidate must be a node with the same opcode
    if not isinstance(candidate, AstBase) or not candidate.is_node():
        return False
    pat_node = typing.cast(AstNode, pattern)
    cand_node = typing.cast(AstNode, candidate)
    if pat_node.opcode != cand_node.opcode:
        return False
    # Recursively match left and right
    left_match = match_pattern(pat_node.left, cand_node.left, mapping)
    if not left_match:
        return False
    return match_pattern(pat_node.right, cand_node.right, mapping)


def substitute_pattern(
    pattern: AstBase | None, mapping: dict[str, AstBase]
) -> AstBase | None:
    """Instantiate a pattern AST using a mapping from variable names to ASTs.

    This helper reconstructs an AST in the shape of the given pattern by
    replacing each AstLeaf and capturing AstConstant with the
    corresponding subtree recorded in `mapping`.  Literal constants are
    copied verbatim.  Operator nodes are rebuilt recursively.

    Args:
        pattern: The pattern AST whose variables will be substituted.
        mapping: The mapping produced by `match_pattern` assigning
            pattern variables to candidate subtrees.
    Returns:
        A new AST where pattern variables and capturing constants are
        replaced with the corresponding candidate subtrees.
    """
    if pattern is None:
        return None
    # Leaf: return the bound candidate (use Protocol for hot-reload safety)
    if isinstance(pattern, AstLeafProtocol):
        var_name = pattern.name
        return copy.deepcopy(mapping[var_name])
    # Capturing constant: substitute the bound constant (use Protocol for hot-reload safety)
    if isinstance(pattern, AstConstantProtocol):
        if pattern.value is None:
            var_name = pattern.name
            return copy.deepcopy(mapping[var_name])
        # Literal constant: return a copy
        return copy.deepcopy(pattern)
    # Node: rebuild with substituted children
    assert isinstance(pattern, AstNodeProtocol)
    new_left = substitute_pattern(pattern.left, mapping)
    new_right = substitute_pattern(pattern.right, mapping)
    return AstNode(
        pattern.opcode, typing.cast(AstBase, new_left), typing.cast(AstBase, new_right)
    )


class CanonicalPatternRule(GenericPatternRule):
    """A Pattern rule that uses canonicalisation for matching.

    Subclasses should override the PATTERN and REPLACEMENT_PATTERN
    properties as usual.  This base class caches a canonicalised copy
    of the pattern to avoid repeated work.  The canonical pattern is
    used solely for structural matching; the original pattern is still
    used for copying microcode (mops) and building the replacement
    instruction.
    """

    FUZZ_PATTERN: bool = (
        False  # Fuzzy pattern generation is unused with canonical matching
    )

    def __init__(self) -> None:
        super().__init__()
        # Cache a canonicalised version of the pattern for matching.  The
        # canonical pattern is computed once in the constructor.  Note
        # that we do not canonicalise the replacement here because it
        # will be instantiated using the mapping and then passed back
        # through the rule logic which expects the original shape.
        self._canonical_pattern: AstBase | None = None

    @property
    def canonical_pattern(self) -> AstBase:
        # Lazily compute and cache the canonical pattern
        if self._canonical_pattern is None:
            if self.PATTERN is None:
                raise ValueError("Pattern must not be None for canonical matching")
            self._canonical_pattern = canonicalize_ast(self.PATTERN)
        return self._canonical_pattern

    def configure(self, fuzz_pattern: bool | None = None, **kwargs) -> None:  # type: ignore[override]
        """Override configure to bypass fuzzy pattern generation.

        The original implementation could generate many fuzzy patterns
        representing different operand orderings.  With canonical
        matching there is no need to generate such variations.  This
        method still accepts a `fuzz_pattern` argument for API
        compatibility but ignores it.
        """
        # Do not generate any fuzzy patterns – the canonical pattern suffices
        super().configure(kwargs)
        self.fuzz_pattern = self.FUZZ_PATTERN
        # Canonical pattern may depend on configuration; recompute
        self._canonical_pattern = canonicalize_ast(self.PATTERN)


@dataclasses.dataclass
class RuleMatchInfo:
    """Holds a rule together with the mapping that matched the rule."""

    rule: CanonicalPatternRule
    mapping: dict[str, AstBase]


class PatternOptimizer2(InstructionOptimizer):  # type: ignore[misc]
    """An optimizer that uses canonical pattern matching instead of fuzzy enumeration.

    This optimizer keeps a list of canonical pattern rules.  For each
    instruction it converts the microcode instruction into an AST,
    canonicalises it, and attempts to match it against each rule's
    canonical pattern.  Upon a successful match, it reconstructs the
    candidate in the shape of the original pattern and delegates to
    the rule to perform any additional checks and construct the
    replacement instruction.
    """

    RULE_CLASSES = [CanonicalPatternRule]

    def __init__(
        self,
        maturities: list[int],
        stats: OptimizationStatistics,
        log_dir: str | None = None,
    ) -> None:
        super().__init__(maturities, stats, log_dir=log_dir)
        # Keep rules in a simple list; no PatternStorage is needed
        self.rules: list[CanonicalPatternRule] = []

    def add_rule(self, rule: CanonicalPatternRule) -> bool:  # type: ignore[override]
        # Let the superclass decide whether the rule should be added
        is_ok = super().add_rule(rule)
        if not is_ok:
            return False
        # Cache the canonical pattern now to detect errors early
        _ = rule.canonical_pattern
        self.rules.append(rule)
        return True

    def get_optimized_instruction(self, blk: ida_hexrays.mblock_t | None, ins: ida_hexrays.minsn_t) -> ida_hexrays.minsn_t | None:  # type: ignore[override]
        # Respect the current maturity as in the original implementation
        if blk is not None:
            self.cur_maturity = blk.mba.maturity
        if self.cur_maturity not in self.maturities:
            return None
        # If no rules are configured, skip conversion altogether
        if len(self.rules) == 0:
            if optimizer_logger.debug_on:
                optimizer_logger.debug(
                    "[PatternOptimizer] No canonical rules configured, skipping"
                )
            return None
        # Convert the instruction to an AST
        tmp_ast = minsn_to_ast(ins)
        if tmp_ast is None:
            if optimizer_logger.debug_on:
                optimizer_logger.debug(
                    "[PatternOptimizer] minsn_to_ast failed, skipping"
                )
            return None
        # Canonicalise the candidate once
        canonical_candidate = canonicalize_ast(tmp_ast)
        # Try each rule in order
        for rule in self.rules:
            canonical_pattern = rule.canonical_pattern
            mapping: dict[str, AstBase] = {}
            # Attempt to match the canonical pattern against the canonical candidate
            if not match_pattern(canonical_pattern, canonical_candidate, mapping):
                continue
            # Reconstruct the candidate AST in the shape of the original pattern
            candidate_ast_for_rule = substitute_pattern(rule.PATTERN, mapping)
            if candidate_ast_for_rule is None:
                continue
            # We need a fresh copy of the pattern AST for mops copying
            # Deepcopy is used because rule.PATTERN is reused across matches
            candidate_pattern = copy.deepcopy(rule.PATTERN)
            candidate_pattern.reset_mops()
            # Copy the mops from the reconstructed candidate into the pattern
            try:
                if not candidate_pattern.check_pattern_and_copy_mops(
                    candidate_ast_for_rule
                ):
                    continue
            except Exception:
                # In case the check fails unexpectedly, skip this match
                continue
            # Allow the rule to perform custom candidate checks (e.g. equal_mops_ignore_size)
            try:
                if not rule.check_candidate(candidate_pattern):
                    continue
            except Exception:
                # If the candidate check raises, log and skip
                optimizer_logger.error(
                    "Error during candidate check for rule %s",
                    rule,
                    exc_info=True,
                )
                continue
            # Build the replacement instruction via the rule's replacement pattern
            try:
                new_instruction = rule.get_replacement(candidate_pattern)
            except Exception:
                optimizer_logger.error(
                    "Error during replacement construction for rule %s",
                    rule,
                    exc_info=True,
                )
                continue
            if new_instruction is not None:
                # Update usage statistics as in the original implementation
                self.rules_usage_info[rule.name] += 1
                if optimizer_logger.info_on:
                    optimizer_logger.info(
                        "Rule %s matched in maturity %s:",
                        rule.name,
                        self.cur_maturity,
                    )
                    optimizer_logger.info("  orig: %s", format_minsn_t(ins))
                    optimizer_logger.info(
                        "  new : %s",
                        format_minsn_t(new_instruction),
                    )
                return new_instruction
        # No rule matched
        return None


# === Example canonical rules ===
#
# The following classes illustrate how to port existing pattern rules to
# the canonical matcher.  They inherit from CanonicalPatternRule
# instead of the original PatternMatchingRule.  The PATTERN and
# REPLACEMENT_PATTERN definitions are unchanged.  Any custom
# check_candidate() methods are preserved.  When these classes are
# registered with the PatternOptimizer above, operand orderings are
# handled automatically by canonicalisation.


class Add_HackersDelightRule_1(CanonicalPatternRule):
    @property
    def PATTERN(self) -> AstNode:
        # x - (~y + 1) → x + y
        return AstNode(
            ida_hexrays.m_sub,
            AstLeaf("x_0"),
            AstNode(
                ida_hexrays.m_add,
                AstNode(ida_hexrays.m_bnot, AstLeaf("x_1")),
                AstConstant("1", 1),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(ida_hexrays.m_add, AstLeaf("x_0"), AstLeaf("x_1"))


class Add_HackersDelightRule_2(CanonicalPatternRule):
    @property
    def PATTERN(self) -> AstNode:
        # (x XOR y) + 2*(x & y) → x + y
        return AstNode(
            ida_hexrays.m_add,
            AstNode(ida_hexrays.m_xor, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(
                ida_hexrays.m_mul,
                AstConstant("2", 2),
                AstNode(ida_hexrays.m_and, AstLeaf("x_0"), AstLeaf("x_1")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(ida_hexrays.m_add, AstLeaf("x_0"), AstLeaf("x_1"))


class Add_HackersDelightRule_3(CanonicalPatternRule):
    @property
    def PATTERN(self) -> AstNode:
        # (x OR y) + (x & y) → x + y
        return AstNode(
            ida_hexrays.m_add,
            AstNode(ida_hexrays.m_or, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(ida_hexrays.m_and, AstLeaf("x_0"), AstLeaf("x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(ida_hexrays.m_add, AstLeaf("x_0"), AstLeaf("x_1"))


class Add_HackersDelightRule_4(CanonicalPatternRule):
    @property
    def PATTERN(self) -> AstNode:
        # 2*(x OR y) - (x XOR y) → x + y
        return AstNode(
            ida_hexrays.m_sub,
            AstNode(
                ida_hexrays.m_mul,
                AstConstant("2", 2),
                AstNode(ida_hexrays.m_or, AstLeaf("x_0"), AstLeaf("x_1")),
            ),
            AstNode(ida_hexrays.m_xor, AstLeaf("x_0"), AstLeaf("x_1")),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(ida_hexrays.m_add, AstLeaf("x_0"), AstLeaf("x_1"))


class Add_HackersDelightRule_5(CanonicalPatternRule):
    @property
    def PATTERN(self) -> AstNode:
        # 2*( (x OR y) OR z ) - (x XOR (y OR z)) → x + (y OR z)
        return AstNode(
            ida_hexrays.m_sub,
            AstNode(
                ida_hexrays.m_mul,
                AstConstant("2", 2),
                AstNode(
                    ida_hexrays.m_or,
                    AstNode(ida_hexrays.m_or, AstLeaf("x_0"), AstLeaf("x_1")),
                    AstLeaf("x_2"),
                ),
            ),
            AstNode(
                ida_hexrays.m_xor,
                AstLeaf("x_0"),
                AstNode(ida_hexrays.m_or, AstLeaf("x_1"), AstLeaf("x_2")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            ida_hexrays.m_add,
            AstLeaf("x_0"),
            AstNode(ida_hexrays.m_or, AstLeaf("x_1"), AstLeaf("x_2")),
        )


class Add_SpecialConstantRule_1(CanonicalPatternRule):
    def check_candidate(self, candidate):
        # c1 and c2 must have the same mop ignoring size
        return equal_mops_ignore_size(candidate["c_1"].mop, candidate["c_2"].mop)

    @property
    def PATTERN(self) -> AstNode:
        # (x XOR c1) + 2*(x & c2) → x + c1  where c1 == c2 ignoring size
        return AstNode(
            ida_hexrays.m_add,
            AstNode(ida_hexrays.m_xor, AstLeaf("x_0"), AstConstant("c_1")),
            AstNode(
                ida_hexrays.m_mul,
                AstConstant("2", 2),
                AstNode(ida_hexrays.m_and, AstLeaf("x_0"), AstConstant("c_2")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(ida_hexrays.m_add, AstLeaf("x_0"), AstConstant("c_1"))


class Add_SpecialConstantRule_2(CanonicalPatternRule):
    def check_candidate(self, candidate):
        # This rule is intentionally conservative: c1 & 0xFF == c2
        return (candidate["c_1"].value & 0xFF) == candidate["c_2"].value

    @property
    def PATTERN(self) -> AstNode:
        # ((x & 0xFF) XOR c1) + 2*(x & c2) → (x & 0xFF) + c1  with constraint above
        return AstNode(
            ida_hexrays.m_add,
            AstNode(
                ida_hexrays.m_xor,
                AstNode(ida_hexrays.m_and, AstLeaf("x_0"), AstConstant("val_ff", 0xFF)),
                AstConstant("c_1"),
            ),
            AstNode(
                ida_hexrays.m_mul,
                AstConstant("2", 2),
                AstNode(ida_hexrays.m_and, AstLeaf("x_0"), AstConstant("c_2")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            ida_hexrays.m_add,
            AstNode(ida_hexrays.m_and, AstLeaf("x_0"), AstConstant("val_ff", 0xFF)),
            AstConstant("c_1"),
        )


class Add_SpecialConstantRule_3(CanonicalPatternRule):
    def check_candidate(self, candidate):
        # c1 == ~c2; introduce val_res = c2 - 1
        if not equal_bnot_mop(candidate["c_1"].mop, candidate["c_2"].mop):
            return False
        candidate.add_constant_leaf(
            "val_res",
            candidate["c_2"].value - 1,
            candidate["x_0"].size,
        )
        return True

    @property
    def PATTERN(self) -> AstNode:
        # (x XOR c1) + 2*(x OR c2) → x + (c2 - 1)  when c1 == ~c2
        return AstNode(
            ida_hexrays.m_add,
            AstNode(ida_hexrays.m_xor, AstLeaf("x_0"), AstConstant("c_1")),
            AstNode(
                ida_hexrays.m_mul,
                AstConstant("2", 2),
                AstNode(ida_hexrays.m_or, AstLeaf("x_0"), AstConstant("c_2")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(ida_hexrays.m_add, AstLeaf("x_0"), AstConstant("val_res"))


class Add_OllvmRule_1(CanonicalPatternRule):
    def check_candidate(self, candidate):
        # Introduce val_1 = 1 (same size as the operands)
        candidate.add_constant_leaf("val_1", 1, candidate.size)
        return True

    @property
    def PATTERN(self) -> AstNode:
        # ~(x XOR y) + 2*(x OR y) → (x + y) - 1
        return AstNode(
            ida_hexrays.m_add,
            AstNode(
                ida_hexrays.m_bnot,
                AstNode(ida_hexrays.m_xor, AstLeaf("x_0"), AstLeaf("x_1")),
            ),
            AstNode(
                ida_hexrays.m_mul,
                AstConstant("2", 2),
                AstNode(ida_hexrays.m_or, AstLeaf("x_1"), AstLeaf("x_0")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            ida_hexrays.m_sub,
            AstNode(ida_hexrays.m_add, AstLeaf("x_0"), AstLeaf("x_1")),
            AstConstant("val_1"),
        )


class Add_OllvmRule_2(CanonicalPatternRule):
    def check_candidate(self, candidate):
        # Only valid when (val_fe + 2) & AND_TABLE[size] == 0
        if (candidate["val_fe"].value + 2) & AND_TABLE[candidate["val_fe"].size] != 0:
            return False
        candidate.add_constant_leaf("val_1", 1, candidate.size)
        return True

    @property
    def PATTERN(self) -> AstNode:
        # ~(x XOR y) - val_fe*(x OR y) → (x + y) - 1  when constraint holds
        return AstNode(
            ida_hexrays.m_sub,
            AstNode(
                ida_hexrays.m_bnot,
                AstNode(ida_hexrays.m_xor, AstLeaf("x_0"), AstLeaf("x_1")),
            ),
            AstNode(
                ida_hexrays.m_mul,
                AstConstant("val_fe"),
                AstNode(ida_hexrays.m_or, AstLeaf("x_0"), AstLeaf("x_1")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            ida_hexrays.m_sub,
            AstNode(ida_hexrays.m_add, AstLeaf("x_0"), AstLeaf("x_1")),
            AstConstant("val_1"),
        )


class Add_OllvmRule_3(CanonicalPatternRule):
    @property
    def PATTERN(self) -> AstNode:
        # (x XOR y) + 2*(x & y) → x + y
        return AstNode(
            ida_hexrays.m_add,
            AstNode(ida_hexrays.m_xor, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(
                ida_hexrays.m_mul,
                AstConstant("2", 2),
                AstNode(ida_hexrays.m_and, AstLeaf("x_0"), AstLeaf("x_1")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(ida_hexrays.m_add, AstLeaf("x_0"), AstLeaf("x_1"))


class Add_OllvmRule_4(CanonicalPatternRule):
    @property
    def PATTERN(self) -> AstNode:
        # (x XOR y) - val_fe*(x & y) → x + y
        return AstNode(
            ida_hexrays.m_sub,
            AstNode(ida_hexrays.m_xor, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(
                ida_hexrays.m_mul,
                AstConstant("val_fe"),
                AstNode(ida_hexrays.m_and, AstLeaf("x_0"), AstLeaf("x_1")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(ida_hexrays.m_add, AstLeaf("x_0"), AstLeaf("x_1"))


class AddXor_Rule_1(CanonicalPatternRule):
    def check_candidate(self, candidate):
        # x1 == ~bnot_x1
        if not equal_bnot_mop(candidate["x_1"].mop, candidate["bnot_x_1"].mop):
            return False
        candidate.add_constant_leaf("val_2", 2, candidate["x_0"].size)
        return True

    @property
    def PATTERN(self) -> AstNode:
        # (x0 - x1) - 2*(x0 OR ~x1) → (x0 XOR x1) + 2
        return AstNode(
            ida_hexrays.m_sub,
            AstNode(ida_hexrays.m_sub, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(
                ida_hexrays.m_mul,
                AstConstant("2", 2),
                AstNode(ida_hexrays.m_or, AstLeaf("x_0"), AstLeaf("bnot_x_1")),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            ida_hexrays.m_add,
            AstNode(ida_hexrays.m_xor, AstLeaf("x_0"), AstLeaf("x_1")),
            AstConstant("val_2"),
        )


class AddXor_Rule_2(CanonicalPatternRule):
    def check_candidate(self, candidate):
        # x0 == ~bnot_x0
        if not equal_bnot_mop(candidate["x_0"].mop, candidate["bnot_x_0"].mop):
            return False
        candidate.add_constant_leaf("val_2", 2, candidate["x_0"].size)
        return True

    @property
    def PATTERN(self) -> AstNode:
        # (x0 - x1) - 2*~( (~x0) & x1 ) → (x0 XOR x1) + 2
        return AstNode(
            ida_hexrays.m_sub,
            AstNode(ida_hexrays.m_sub, AstLeaf("x_0"), AstLeaf("x_1")),
            AstNode(
                ida_hexrays.m_mul,
                AstConstant("2", 2),
                AstNode(
                    ida_hexrays.m_bnot,
                    AstNode(ida_hexrays.m_and, AstLeaf("bnot_x_0"), AstLeaf("x_1")),
                ),
            ),
        )

    @property
    def REPLACEMENT_PATTERN(self) -> AstNode:
        return AstNode(
            ida_hexrays.m_add,
            AstNode(ida_hexrays.m_xor, AstLeaf("x_0"), AstLeaf("x_1")),
            AstLeaf("val_2"),
        )
