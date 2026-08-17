"""IDA Pro backend for MBA expressions and rule pattern matching.

This module provides:

1. IDAPatternAdapter - Wraps a VerifiableRule for use with IDA pattern matching
2. IDANodeVisitor - Converts SymbolicExpression -> AstNode for IDA

All IDA-dependent code for rule execution should be in this module, keeping
the rule definitions in d810.mba.rules pure and backend-agnostic.
"""

from __future__ import annotations

import itertools
import json
import os
import time
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from d810.core.typing import TYPE_CHECKING, Any, Dict, List, Optional

import ida_hexrays

from d810.core import getLogger
from d810.errors import AstEvaluationException
from d810.hexrays.expr.ast import (
    AstConstant,
    AstConstantProtocol,
    AstLeaf,
    AstLeafProtocol,
    AstNode,
)
from d810.hexrays.ir.minsn_utils import minsn_to_ast
from d810.hexrays.ir.mop_snapshot import MopSnapshot
from d810.mba.dsl import SymbolicExpression, SymbolicExpressionProtocol
from d810.mba.constraints import (
    ComparisonConstraintProtocol,
    EqualityConstraintProtocol,
    is_constraint_expr,
)
from d810.mba.provider_outcome import (
    MatcherOutcomeMetadata,
    MbaProviderKind,
    MbaProviderOutcome,
    ProviderOutcomeStatus,
)
from d810.mba.provider_history import ProviderOutcomeHistory
from d810.hexrays.ir.number_operand import safe_make_number
from d810.backends.mba.native_z3 import prove_native_ast_equivalence

logger = getLogger(__name__)

# Type hints only
if TYPE_CHECKING:
    from d810.mba.rules import VerifiableRule


# =============================================================================
# Egglog-based Pattern Generation Helpers
# =============================================================================

# Map DSL operation names to commutative status
# Note: DSL uses "and", "or" (not "and_", "or_")
_COMMUTATIVE_OPS = {"add", "mul", "and", "or", "xor"}

# The portable structural matcher is only sound for the same typed island
# vocabulary accepted by ``lower_hexrays_island``.  Snapshot membership is not
# enough: the full direct catalogue also contains shifts, casts, predicates,
# and division/modulo rules that must retain legacy native matching.
_STRUCTURAL_DSL_OPERATIONS = frozenset(
    {"add", "sub", "mul", "and", "or", "xor", "bnot", "neg"}
)
_STRUCTURAL_PROOF_WIDTHS = (8, 16, 32, 64)


def _supports_structural_dsl_pattern(expr: object) -> bool:
    """Return whether one declared DSL pattern fits the typed structural island."""

    active_nodes: set[int] = set()

    def visit(node: object) -> bool:
        if not isinstance(node, SymbolicExpressionProtocol):
            return False
        identity = id(node)
        if identity in active_nodes:
            return False
        active_nodes.add(identity)
        try:
            operation = getattr(node, "operation", None)
            if operation is None:
                return True
            if operation not in _STRUCTURAL_DSL_OPERATIONS:
                return False
            left = getattr(node, "left", None)
            right = getattr(node, "right", None)
            if left is None or not visit(left):
                return False
            return right is None or visit(right)
        finally:
            active_nodes.remove(identity)

    return visit(expr)


def _snapshot_rule_widths_are_structurally_eligible(
    snapshot: object, rule_id: object, rule: object
) -> bool:
    """Require one complete canonical template set before starving legacy storage."""

    if type(rule_id) is not int:
        return False
    statuses = getattr(snapshot, "canonical_status_by_rule_width", None)
    if not isinstance(statuses, Mapping):
        return False
    widths = getattr(rule, "proof_widths", _STRUCTURAL_PROOF_WIDTHS)
    try:
        widths = tuple(widths)
    except TypeError:
        return False
    if not widths:
        widths = _STRUCTURAL_PROOF_WIDTHS
    return all(
        type(width) is int
        and width > 0
        and statuses.get((rule_id, width)) == "eligible"
        for width in widths
    )


def _generate_commutative_permutations(
    expr: SymbolicExpression,
) -> List[SymbolicExpression]:
    """Generate all commutative permutations of a SymbolicExpression.

    This recursively generates all permutations where commutative operators
    have their operands swapped.

    Args:
        expr: The base expression.

    Returns:
        List of all commutative permutations (including the original).
    """
    # Note: is_variable() and is_constant() are methods, not properties
    if expr.is_variable() or expr.is_constant():
        return [expr]

    # ``bool_to_int`` carries a comparison constraint rather than ordinary
    # expression children.  It is a legacy-only predicate shape, but must
    # still register as its declared base pattern after Task 8 filters it out
    # of structural matching.
    if expr.operation == "bool_to_int":
        return [expr]

    # Unary operations
    if expr.right is None:
        left_perms = _generate_commutative_permutations(expr.left)
        return [
            SymbolicExpression(expr.operation, left=lp, right=None) for lp in left_perms
        ]

    # Binary operations
    left_perms = _generate_commutative_permutations(expr.left)
    right_perms = _generate_commutative_permutations(expr.right)

    results = []
    for lp, rp in itertools.product(left_perms, right_perms):
        # Original order
        results.append(SymbolicExpression(expr.operation, left=lp, right=rp))

        # Swapped order (if commutative)
        if expr.operation in _COMMUTATIVE_OPS:
            results.append(SymbolicExpression(expr.operation, left=rp, right=lp))

    return results


class _LeafWrapper:
    """Lightweight wrapper to give AstLeaf nodes a leafs_by_name interface.

    Used by IDAPatternAdapter.get_replacement() to handle AstLeaf candidates
    that don't natively have leafs_by_name attribute.
    """

    __slots__ = ("leafs_by_name", "ea", "dst_mop")

    def __init__(self, leaf: AstLeaf):
        self.leafs_by_name = {leaf.name: leaf} if leaf.name else {}
        self.ea = leaf.ea
        # Handle both MopSnapshot (from Phase 2) and raw mop_t
        # Phase 2 changed AstLeaf.mop to store MopSnapshot for safety
        from d810.hexrays.ir.mop_snapshot import MopSnapshot

        if isinstance(leaf.mop, MopSnapshot):
            self.dst_mop = leaf.mop.to_mop()  # Reconstruct owned mop_t
        else:
            self.dst_mop = leaf.mop  # Already a mop_t (legacy path)


class _ShadowBindingCandidate:
    """Read-only structural bindings shaped for the existing emitter."""

    __slots__ = ("leafs_by_name", "ea", "dst_mop", "is_candidate_ok")

    def __init__(self, leafs_by_name: dict[str, Any], source: Any) -> None:
        self.leafs_by_name = leafs_by_name
        self.ea = getattr(source, "ea", None)
        self.dst_mop = getattr(source, "dst_mop", None)
        self.is_candidate_ok = True


class _BindingMopCarrier:
    """Expose a direct matcher mop through the AST leaf binding protocol."""

    __slots__ = ("mop",)

    def __init__(self, mop: Any) -> None:
        self.mop = mop


class IDANodeVisitor:
    """Converts SymbolicExpression trees to IDA AstNode trees.

    This visitor handles the conversion from the pure DSL representation
    to IDA's internal AST format for pattern matching.

    Example:
        >>> from d810.mba.dsl import Var
        >>> x, y = Var("x"), Var("y")
        >>> pattern = (x | y) - (x & y)
        >>> visitor = IDANodeVisitor()
        >>> ast_node = visitor.visit(pattern)
    """

    # Map DSL operation strings to ida_hexrays attribute names (e.g., "m_add", "m_xor")
    _OPERATION_TO_IDA_ATTR = {
        "add": "m_add",
        "sub": "m_sub",
        "mul": "m_mul",
        "udiv": "m_udiv",
        "sdiv": "m_sdiv",
        "umod": "m_umod",
        "smod": "m_smod",
        "and": "m_and",
        "or": "m_or",
        "xor": "m_xor",
        "shl": "m_shl",
        "shr": "m_shr",
        "sar": "m_sar",
        "low": "m_low",
        "high": "m_high",
        "bnot": "m_bnot",
        "neg": "m_neg",
        "lnot": "m_lnot",
        "zext": "m_xdu",
        # Comparison operations
        "setnz": "m_setnz",
        "setz": "m_setz",
        "setae": "m_setae",
        "setb": "m_setb",
        "seta": "m_seta",
        "setbe": "m_setbe",
        "setg": "m_setg",
        "setge": "m_setge",
        "setl": "m_setl",
        "setle": "m_setle",
    }

    def visit(self, expr: SymbolicExpression) -> AstNode:
        """Convert a SymbolicExpression to an AstNode.

        Args:
            expr: The SymbolicExpression to convert. Can also be int for constants.

        Returns:
            An AstNode representing the same expression.
        """
        if expr is None:
            return None

        # Handle raw integers (e.g., from constant expressions)
        if isinstance(expr, int):
            return AstConstant(str(expr), expr)

        # Use Protocol for structural typing - survives hot reloads
        if not isinstance(expr, SymbolicExpressionProtocol):
            raise ValueError(f"Expected SymbolicExpression, got {type(expr).__name__}")

        if expr.is_leaf():
            return self._visit_leaf(expr)

        # Handle bool_to_int specially - converts ConstraintExpr to comparison opcode
        if expr.operation == "bool_to_int":
            return self._visit_bool_to_int(expr)

        # Convert children recursively
        left = self.visit(expr.left) if expr.left else None
        right = self.visit(expr.right) if expr.right else None

        # Map operation string to IDA opcode
        opcode = self._get_ida_opcode(expr.operation)

        return AstNode(opcode, left, right)

    def _visit_leaf(self, expr: SymbolicExpression) -> AstLeaf:
        """Convert a leaf SymbolicExpression to an AstLeaf.

        Args:
            expr: The leaf SymbolicExpression to convert.

        Returns:
            An AstLeaf or AstConstant representing the leaf.
        """
        if expr.is_constant():
            # Concrete constant (has a value)
            return AstConstant(expr.name, expr.value)
        elif getattr(expr, "is_pattern_constant", False):
            # Pattern-matching constant (value computed from constraints)
            # Use AstConstant so it can receive computed value and create mop_n
            return AstConstant(expr.name, None)
        else:
            # Variable or pattern-matching placeholder
            return AstLeaf(expr.name)

    def _visit_bool_to_int(self, expr: SymbolicExpression) -> AstNode:
        """Convert a bool_to_int operation to an AstNode.

        This handles the bridge between boolean constraints (formulas) and
        arithmetic expressions (terms). Converts to IDA's SET* comparison opcodes.

        Args:
            expr: SymbolicExpression with operation="bool_to_int" and constraint set.

        Returns:
            AstNode representing the comparison operation (SETNZ, SETZ, etc.)
        """
        constraint = expr.constraint
        if constraint is None:
            raise ValueError("bool_to_int operation requires a constraint")

        if isinstance(constraint, ComparisonConstraintProtocol):
            left_node = self._visit_constraint_operand(constraint.left)
            right_node = self._visit_constraint_operand(constraint.right)

            # Map comparison operators to IDA SET opcodes
            op_map = {
                "ne": ida_hexrays.m_setnz,  # x != y -> SETNZ(x - y)
                "eq": ida_hexrays.m_setz,  # x == y -> SETZ(x - y)
                "lt": ida_hexrays.m_setb,  # x < y -> SETB(x, y)
                "ge": ida_hexrays.m_setae,  # x >= y -> SETAE(x, y)
            }

            ida_opcode = op_map.get(constraint.op_name)
            if ida_opcode is None:
                raise ValueError(
                    f"Unsupported comparison for IDA pattern: {constraint.op_name}"
                )

            # For != and ==, IDA uses SETNZ/SETZ with a single operand (difference)
            if constraint.op_name in ["ne", "eq"]:
                # Check if comparing to zero
                if (
                    isinstance(constraint.right, SymbolicExpressionProtocol)
                    and constraint.right.is_constant()
                    and constraint.right.value == 0
                ):
                    return AstNode(ida_opcode, left_node, None)
                # Check if right is raw int zero
                if constraint.right == 0:
                    return AstNode(ida_opcode, left_node, None)
                # Otherwise, create subtraction first
                diff_node = AstNode(ida_hexrays.m_sub, left_node, right_node)
                return AstNode(ida_opcode, diff_node, None)
            else:
                return AstNode(ida_opcode, left_node, right_node)

        if isinstance(constraint, EqualityConstraintProtocol):
            # x == y -> SETZ(x - y)
            left_node = self._visit_constraint_operand(constraint.left)
            right_node = self._visit_constraint_operand(constraint.right)

            # Check if comparing to zero
            if (
                isinstance(constraint.right, SymbolicExpressionProtocol)
                and constraint.right.is_constant()
                and constraint.right.value == 0
            ):
                return AstNode(ida_hexrays.m_setz, left_node, None)
            # Check if right is raw int zero
            if constraint.right == 0:
                return AstNode(ida_hexrays.m_setz, left_node, None)

            diff_node = AstNode(ida_hexrays.m_sub, left_node, right_node)
            return AstNode(ida_hexrays.m_setz, diff_node, None)

        raise ValueError(
            f"Unsupported constraint type for IDA pattern: {type(constraint)}"
        )

    def _visit_constraint_operand(self, operand) -> Optional[AstNode]:
        """Visit a constraint operand, handling both SymbolicExpression and raw values.

        Args:
            operand: Either a SymbolicExpression or a raw value (int, etc.)

        Returns:
            AstNode for SymbolicExpression, AstConstant for raw values, None for None.
        """
        if operand is None:
            return None
        if isinstance(operand, SymbolicExpressionProtocol):
            return self.visit(operand)
        if isinstance(operand, int):
            return AstConstant(str(operand), operand)
        # Fallback: try to visit it
        return self.visit(operand)

    def _get_ida_opcode(self, operation: str) -> int:
        """Map a DSL operation string to an IDA opcode.

        Args:
            operation: The operation string (e.g., "add", "sub", "xor").

        Returns:
            The IDA opcode constant (e.g., ida_hexrays.m_add).

        Raises:
            ValueError: If the operation is not supported.
        """
        ida_attr = self._OPERATION_TO_IDA_ATTR.get(operation)
        if ida_attr is None:
            raise ValueError(f"Unknown operation: {operation}")

        # Get the IDA opcode directly from ida_hexrays
        opcode = getattr(ida_hexrays, ida_attr, None)
        if opcode is None:
            raise ValueError(f"Opcode {ida_attr} not found in ida_hexrays")

        return opcode


class IDAPatternAdapter:
    """Adapts a VerifiableRule for use with IDA pattern matching.

    This adapter wraps a pure VerifiableRule and provides the IDA-specific
    interface required by PatternOptimizer:
    - pattern_candidates property
    - get_valid_candidates() method
    - get_replacement() method
    - check_and_replace() method

    The rule itself remains pure (no IDA dependencies). All IDA-specific
    logic is encapsulated in this adapter.

    Example:
        >>> from d810.mba.rules import VerifiableRule
        >>> from d810.backends.mba.ida import IDAPatternAdapter
        >>>
        >>> # Create adapter from rule
        >>> adapter = IDAPatternAdapter(my_rule)
        >>>
        >>> # Use in IDA context
        >>> new_ins = adapter.check_and_replace(blk, instruction)
    """

    PORTFOLIO_TIER = "fast"

    def __init__(self, rule: VerifiableRule):
        """Initialize the adapter with a rule.

        Args:
            rule: The VerifiableRule to adapt for IDA.
        """
        self.rule = rule
        self._pattern_candidates_cache: Optional[List[AstNode]] = None
        self._replacement_pattern_cache: Optional[AstNode] = None
        self._visitor = IDANodeVisitor()
        self._attempt_started: float | None = None
        self._attempt_destination_size: int | None = None
        self._attempt_input_ast: AstNode | None = None
        self._last_provider_outcome: MbaProviderOutcome | None = None
        self.provider_outcome_history = ProviderOutcomeHistory[MbaProviderOutcome]()
        self._attempt_outcome_index: int | None = None
        self._provider_outcome_capture_depth = 0
        self._shadow_match_report = None
        self._shadow_lowering = None
        self._shadow_source_ast = None
        self._shadow_structural_native_paths: dict[str, tuple[int, ...]] | None = None
        self._shadow_native_path_unavailable = False
        self._legacy_binding_paths: (
            dict[str, frozenset[tuple[int, ...]]] | None
        ) = None
        self._legacy_match_observed = False
        self._certified_catalogue_snapshot = None
        self._certified_catalogue_rule_id: int | None = None
        self._shadow_parity_ledger = None
        self._shadow_parity_recorded = False
        self._shadow_canonical_templates: dict[int, Any] = {}
        self._structural_matching_enabled = False
        self._structural_parity_authorized = False
        self._structural_selection_active = False
        self._structural_dispatch_bucket_size = 0
        self._structural_dispatch_attempt_count = 0
        self._generate_commutative_permutations = True

    def _reset_attempt_outcome(self, instruction: Any | None = None) -> None:
        """Discard telemetry from the previous live pattern attempt."""

        self._attempt_started = time.monotonic()
        size = getattr(getattr(instruction, "d", None), "size", None)
        self._attempt_destination_size = (
            int(size) if type(size) is int and size > 0 else None
        )
        try:
            self._attempt_input_ast = (
                None if instruction is None else minsn_to_ast(instruction)
            )
        except Exception:
            self._attempt_input_ast = None
        self._last_provider_outcome = None
        self._attempt_outcome_index = None
        self._shadow_match_report = None
        self._shadow_lowering = None
        self._shadow_source_ast = None
        self._shadow_structural_native_paths = None
        self._shadow_native_path_unavailable = False
        self._legacy_binding_paths = None
        self._legacy_match_observed = False
        self._shadow_parity_recorded = False
        self._structural_selection_active = False
        self._structural_dispatch_bucket_size = 0
        self._structural_dispatch_attempt_count = 0

    def _provider_outcome_capture_enabled(self) -> bool:
        """Whether this long-lived adapter is inside an explicit capture scope."""

        return bool(getattr(self, "_provider_outcome_capture_depth", 0))

    def _prepare_shadow_canonical_templates(self) -> None:
        """Freeze width-specific templates before any candidate callback."""

        if self._shadow_canonical_templates:
            return
        from d810.mba.canonical_pattern import (
            CanonicalPatternUnsupported,
            compile_canonical_pattern,
        )

        try:
            pattern = getattr(self.rule, "pattern", None)
            replacement = getattr(self.rule, "replacement", None)
            if callable(pattern):
                pattern = pattern()
            if callable(replacement):
                replacement = replacement()
        except Exception:
            return
        if pattern is None:
            return
        try:
            widths = tuple(getattr(self.rule, "proof_widths", (8, 16, 32, 64)))
        except (TypeError, ValueError):
            widths = (8, 16, 32, 64)
        if not widths:
            widths = (8, 16, 32, 64)
        if replacement is None:
            # Direct unit/runtime probes sometimes provide only a pattern.  A
            # shadow matcher needs no replacement semantics, so use the
            # pattern as an inert template while preserving frozen constraints.
            template_rule = SimpleNamespace(
                pattern=pattern,
                replacement=pattern,
                source_name=getattr(self.rule, "source_name", None)
                or getattr(self.rule, "name", type(self.rule).__name__),
                aliases=tuple(getattr(self.rule, "aliases", ())),
                family=getattr(self.rule, "family", "shadow"),
                proof_widths=widths,
                guarded=bool(getattr(self.rule, "guarded", False)),
                constraints=tuple(
                    getattr(
                        self.rule,
                        "constraints",
                        getattr(self.rule, "CONSTRAINTS", ()),
                    )
                    or ()
                ),
            )
        else:
            template_rule = self.rule
        templates: dict[int, Any] = {}
        for width in widths:
            if type(width) is not int or width <= 0:
                continue
            try:
                templates[width] = compile_canonical_pattern(
                    template_rule,
                    width=width,
                    declaration_index=int(
                        getattr(self, "_certified_catalogue_rule_id", 0) or 0
                    ),
                )
            except (CanonicalPatternUnsupported, TypeError, ValueError):
                continue
        self._shadow_canonical_templates = templates

    @staticmethod
    def _shadow_observation_enabled() -> bool:
        """Keep expensive parity collection out of normal legacy execution."""

        return os.environ.get("D810_SHADOW_DSL_MATCHING", "0") == "1"

    def begin_provider_outcome_capture(self) -> None:
        """Enable bounded history retention for one explicit capture session."""

        if not self._provider_outcome_capture_enabled():
            self.provider_outcome_history.clear()
        self._provider_outcome_capture_depth = (
            int(getattr(self, "_provider_outcome_capture_depth", 0)) + 1
        )

    def end_provider_outcome_capture(self) -> None:
        """Disable bounded history retention after an explicit capture session."""

        depth = int(getattr(self, "_provider_outcome_capture_depth", 0))
        if depth <= 0:
            raise RuntimeError("provider outcome capture was not active")
        self._provider_outcome_capture_depth = depth - 1

    def attach_certified_catalogue_snapshot(
        self,
        snapshot,
        rule_id: int,
        ledger,
        parity_certificate,
        parity_expectation,
        runtime_mode: str | None,
    ) -> None:
        """Attach one configuration-time snapshot and select its matcher mode."""

        self._certified_catalogue_snapshot = snapshot
        self._certified_catalogue_rule_id = rule_id
        self._shadow_parity_ledger = ledger
        self._prepare_shadow_canonical_templates()
        # The snapshot only contains already-admitted VerifiableRule DSL
        # objects. The environment flag requests the experimental path, but a
        # persisted zero-mismatch certificate must also bind this exact
        # snapshot to the active matcher runtime. Keep generated permutations
        # as the safe default and the release-scoped rollback; never register
        # both forms at once. The explicit rollback wins if both flags are set.
        self._structural_parity_authorized = bool(
            parity_certificate is not None
            and runtime_mode is not None
            and parity_certificate.authorizes(
                snapshot, runtime_mode, parity_expectation
            )
        )
        structural_matching_enabled = (
            _supports_structural_dsl_pattern(getattr(self.rule, "pattern", None))
            and _snapshot_rule_widths_are_structurally_eligible(
                snapshot,
                self._certified_catalogue_rule_id,
                self.rule,
            )
            and os.environ.get("D810_STRUCTURAL_DSL_MATCHING", "0") == "1"
            and os.environ.get("D810_LEGACY_DSL_PERMUTATIONS", "0") != "1"
            and self._structural_parity_authorized
        )
        if self._structural_matching_enabled != structural_matching_enabled:
            # A reused adapter survives project reloads. Its generated legacy
            # variants and its structural base form cannot share one cache.
            self._pattern_candidates_cache = None
        self._structural_matching_enabled = structural_matching_enabled

    @property
    def uses_structural_matching(self) -> bool:
        """Whether this snapshot-selected DSL rule uses the portable matcher."""

        return bool(getattr(self, "_structural_matching_enabled", False))

    def match_structural_and_replace(
        self,
        test_ast: Any,
        *,
        bucket_size: int,
        attempted_rule_count: int,
        lowering: Any | None = None,
        lowering_provided: bool = False,
    ) -> Any | None:
        """Select through the bounded portable matcher for one certified rule.

        This is deliberately an adapter method: lowerer identity, constraint
        materialization, and native replacement construction remain on the IDA
        boundary.  A lowerer miss or any unusable binding remains a no-op.
        """

        if not self.uses_structural_matching:
            return None
        self._structural_selection_active = True
        self._structural_dispatch_bucket_size = max(0, int(bucket_size))
        self._structural_dispatch_attempt_count = max(0, int(attempted_rule_count))
        report = self.observe_structural_match(
            test_ast,
            lowering=lowering,
            lowering_provided=lowering_provided,
        )
        paths = getattr(self, "_shadow_structural_native_paths", None)
        if report is None or report.bindings is None or not paths:
            return None
        leafs_by_name: dict[str, Any] = {}
        for name, path in paths.items():
            native = self._native_node_at_path(test_ast, path)
            if native is None:
                return None
            leafs_by_name[name] = native
        try:
            candidate = _ShadowBindingCandidate(leafs_by_name, test_ast)
            if not candidate.ea or not self._check_candidate(candidate):
                return None
            # Structural bindings are a read-only projection of the source AST.
            # Reuse the clone-based emitter so its active-runtime binding carrier
            # preserves the original live mops instead of mutating the cached
            # legacy replacement pattern.
            replacement = self._get_shadow_replacement(candidate)
        except Exception:
            return None
        if replacement is None:
            return None
        destination_size = self._attempt_destination_size
        if type(destination_size) is not int or destination_size <= 0:
            destination_size = getattr(test_ast, "dest_size", None)
        if type(destination_size) is not int or destination_size <= 0:
            return None
        try:
            replacement_ast = minsn_to_ast(replacement)
        except Exception:
            return None
        if replacement_ast is None or not prove_native_ast_equivalence(
            test_ast,
            replacement_ast,
            width=destination_size * 8,
        ):
            return None
        self._record_catalogue_success(
            test_ast,
            self.REPLACEMENT_PATTERN,
        )
        return replacement

    def prepare_structural_candidate(
        self,
        test_ast: Any,
        *,
        destination_size: int | None = None,
    ) -> Any | None:
        """Lower one root bucket once, before its rule-specific comparisons."""

        try:
            from d810.backends.mba.hexrays_island import lower_hexrays_island

            size = (
                destination_size
                if destination_size is not None
                else self._attempt_destination_size
            )
            if type(size) is not int:
                return None
            return lower_hexrays_island(test_ast, destination_size=size)
        except Exception:
            return None

    def observe_structural_match(
        self,
        test_ast: Any,
        *,
        comparison_budget: int = 64,
        lowering: Any | None = None,
        lowering_provided: bool = False,
    ):
        """Record the bounded portable matcher result without changing selection.

        The legacy AstNode matcher stays authoritative during the Task 7 shadow
        period. Canonical candidates and frozen rule templates are matched only
        as a read-only observation. Binding paths must resolve to the
        lowerer's original native objects through exact raw-path provenance.
        """

        self._shadow_native_path_unavailable = False
        try:
            from d810.mba.ac_matching import match_canonical_term_pattern
            from d810.mba.canonical_pattern import (
                CanonicalFixedBindings,
                CanonicalPatternMatchReport,
                evaluate_frozen_constraints,
                merge_canonical_bindings,
                resolve_canonical_match_paths,
            )
            from d810.mba.ac_matching import AcMatchStopReason

            if not lowering_provided:
                lowering = self.prepare_structural_candidate(test_ast)
            if lowering is None:
                return None
            if (
                lowering.term is None
                or lowering.raw_term is None
            ):
                return None
            self._prepare_shadow_canonical_templates()
            template = self._shadow_canonical_templates.get(lowering.term.width)
            if template is None:
                return None
            snapshot = getattr(self, "_certified_catalogue_snapshot", None)
            if snapshot is not None:
                from d810.mba.certified_catalogue import root_shape_for_term

                bucket = snapshot.canonical_rule_ids_by_root_shape.get(
                    root_shape_for_term(lowering.term),
                    (),
                )
                if getattr(self, "_certified_catalogue_rule_id", None) not in bucket:
                    return None
            report = match_canonical_term_pattern(
                template,
                lowering.term,
                comparison_budget=comparison_budget,
            )
            if report.matches:
                valid_matches = []
                for match in report.matches:
                    try:
                        base_bindings = merge_canonical_bindings(
                            match.bindings,
                            report.compatibility_bindings,
                        )
                    except ValueError:
                        continue
                    terms = dict(base_bindings.terms)
                    if not evaluate_frozen_constraints(
                        match.compiled_pattern.constraints,
                        terms,
                        width=lowering.term.width,
                    ):
                        continue
                    valid_matches.append(
                        replace(
                            match,
                            bindings=CanonicalFixedBindings(
                                terms,
                                base_bindings.candidate_paths,
                                lowering.term.width,
                            ),
                        )
                    )
                if not valid_matches:
                    report = CanonicalPatternMatchReport(
                        (),
                        report.comparisons,
                        report.commuted_branches,
                        report.flattened_nodes,
                        AcMatchStopReason.MISS,
                    )
                else:
                    report = replace(
                        report,
                        matches=tuple(valid_matches),
                        compatibility_bindings=None,
                    )
            structural_native_paths: dict[str, tuple[int, ...]] | None = None
            native_path_unavailable = False
            if report.matches:
                required_names = set(
                    getattr(template, "fixed_constant_values", {})
                )
                raw_paths_by_identity: dict[int, list[tuple[int, ...]]] = {}
                for raw_path, native in lowering.raw_native_nodes_by_path.items():
                    raw_paths_by_identity.setdefault(id(native), []).append(raw_path)
                canonical_to_raw_paths: dict[tuple[int, ...], tuple[int, ...]] = {}
                for canonical_path, native in lowering.native_nodes_by_path.items():
                    raw_paths = raw_paths_by_identity.get(id(native), ())
                    if len(raw_paths) == 1:
                        canonical_to_raw_paths[canonical_path] = raw_paths[0]
                resolved_matches = resolve_canonical_match_paths(
                    report.matches,
                    canonical_to_raw_paths=canonical_to_raw_paths,
                    placeholder_order=(
                        name for _kind, name in template.terminal_kinds
                    ),
                    required_names=required_names,
                )
                if not resolved_matches:
                    native_path_unavailable = True
                    report = replace(
                        report,
                        matches=(),
                        compatibility_bindings=None,
                    )
                else:
                    report = replace(
                        report,
                        matches=resolved_matches,
                        compatibility_bindings=None,
                    )
                    binding = report.bindings
                    if binding is not None:
                        structural_native_paths = dict(binding.candidate_paths)
            self._shadow_lowering = lowering
            self._shadow_source_ast = test_ast
            self._shadow_match_report = report
            self._shadow_structural_native_paths = structural_native_paths
            self._shadow_native_path_unavailable = native_path_unavailable
            return report
        except Exception:
            # Shadow telemetry must never widen the legacy callback failure set.
            return None

    def _matcher_metadata(self) -> MatcherOutcomeMetadata | None:
        report = getattr(self, "_shadow_match_report", None)
        if report is None:
            return None
        return MatcherOutcomeMetadata(
            comparisons=report.comparisons,
            lazy_swaps=report.commuted_branches,
            flattened_arity=report.flattened_nodes,
            stop_reason=(
                "native_path_unavailable"
                if getattr(self, "_shadow_native_path_unavailable", False)
                else report.stop_reason.value
            ),
        )

    def record_legacy_match_bindings(
        self, candidate_pattern: Any, source_ast: Any | None = None
    ) -> None:
        """Capture legacy bindings as unique original-native paths when possible."""

        self._legacy_match_observed = True
        self._legacy_binding_paths = None
        lowering = getattr(self, "_shadow_lowering", None)
        if lowering is None:
            return
        declared_names: set[str] = set()

        def collect_declared_names(pattern: Any) -> None:
            if bool(getattr(pattern, "is_node", lambda: False)()):
                for child_name in ("left", "right"):
                    child = getattr(pattern, child_name, None)
                    if child is not None:
                        collect_declared_names(child)
                return
            name = getattr(pattern, "name", None)
            if type(name) is str and name and name != "_candidate":
                declared_names.add(name)

        collect_declared_names(candidate_pattern)
        if not declared_names:
            return
        # The legacy matcher walks its pattern and source in lockstep. Preserve
        # that slot evidence whenever the caller still has the source tree.
        # Without that evidence, equality of mop keys cannot establish which
        # live slot was selected, so leave parity unknown rather than guess.
        if source_ast is not None:
            resolved_from_slots: dict[str, set[tuple[int, ...]]] = {}

            def walk(pattern: Any, source: Any, path: tuple[int, ...]) -> bool:
                if bool(getattr(pattern, "is_node", lambda: False)()) != bool(
                    getattr(source, "is_node", lambda: False)()
                ):
                    return False
                if bool(getattr(pattern, "is_node", lambda: False)()):
                    for index, child_name in enumerate(("left", "right")):
                        pattern_child = getattr(pattern, child_name, None)
                        source_child = getattr(source, child_name, None)
                        if (pattern_child is None) != (source_child is None):
                            return False
                        if pattern_child is not None and not walk(
                            pattern_child, source_child, path + (index,)
                        ):
                            return False
                    return True
                name = getattr(pattern, "name", None)
                if type(name) is str and name in declared_names:
                    # Repeated pattern variables have several legitimate
                    # source slots.  Keep all of them; the structural matcher
                    # may select any one only after checking their equality.
                    resolved_from_slots.setdefault(name, set()).add(path)
                return True

            if walk(candidate_pattern, source_ast, ()) and set(
                resolved_from_slots
            ) == declared_names:
                self._legacy_binding_paths = {
                    name: frozenset(paths)
                    for name, paths in resolved_from_slots.items()
                }
                return

        return

    def _shadow_metadata(self, *, legacy_match: bool) -> dict[str, object]:
        report = getattr(self, "_shadow_match_report", None)
        structural_match = bool(report is not None and report.bindings is not None)
        same_bindings: bool | None = None
        if legacy_match and not structural_match:
            same_bindings = False
        elif legacy_match and bool(getattr(self, "_legacy_match_observed", False)):
            legacy_paths = getattr(self, "_legacy_binding_paths", None)
            structural_paths = getattr(self, "_shadow_structural_native_paths", None)
            if legacy_paths is not None and structural_paths is not None:
                same_bindings = set(legacy_paths) == set(structural_paths) and all(
                    path in legacy_paths[name]
                    for name, path in structural_paths.items()
                )
        return {
            "legacy_match": legacy_match,
            "structural_match": structural_match,
            "same_rule": legacy_match and structural_match,
            "same_bindings": same_bindings,
        }

    def _record_shadow_parity(self, *, legacy_match: bool) -> None:
        if getattr(self, "_shadow_parity_recorded", False):
            return
        ledger = getattr(self, "_shadow_parity_ledger", None)
        if ledger is None:
            return
        shadow = self._shadow_metadata(legacy_match=legacy_match)
        structural_proven = False
        structural_refused = False
        if not legacy_match and bool(shadow["structural_match"]):
            structural_proven = self._prove_structural_only_candidate()
            structural_refused = bool(
                not structural_proven
                and getattr(self, "_shadow_structural_refused", False)
            )
        ledger.record(
            **shadow,
            structural_proven=structural_proven,
            structural_refused=structural_refused,
        )
        self._shadow_parity_recorded = True

    @staticmethod
    def _native_node_at_path(source: Any, path: tuple[int, ...]) -> Any | None:
        current = source
        try:
            for index in path:
                current = getattr(current, "left" if index == 0 else "right", None)
                if current is None:
                    return None
            return current
        except Exception:
            return None

    def _prove_structural_only_candidate(self) -> bool:
        """Promote a structural-only hit after reconstruction and proof only."""

        # A completed native reconstruction/proof that rejects a candidate is
        # a stable refusal, not "pending safe coverage". Pending means the
        # proof-only path could not reach a decision at all.
        self._shadow_structural_refused = False
        source = getattr(self, "_shadow_source_ast", None)
        paths = getattr(self, "_shadow_structural_native_paths", None)
        destination_size = getattr(self, "_attempt_destination_size", None)
        if source is None or not paths or destination_size is None:
            return False
        leafs_by_name: dict[str, Any] = {}
        for name, path in paths.items():
            native = self._native_node_at_path(source, path)
            if native is None:
                return False
            leafs_by_name[name] = native
        candidate = _ShadowBindingCandidate(leafs_by_name, source)
        if not candidate.ea or not self._check_candidate(candidate):
            self._shadow_structural_refused = True
            return False
        replacement_ins = self._get_shadow_replacement(candidate)
        if replacement_ins is None:
            self._shadow_structural_refused = True
            return False
        replacement = minsn_to_ast(replacement_ins)
        input_cost = self._ast_cost(source)
        output_cost = self._ast_cost(replacement)
        if (
            replacement is None
            or input_cost is None
            or output_cost is None
            or output_cost >= input_cost
        ):
            self._shadow_structural_refused = True
            return False
        proven = prove_native_ast_equivalence(
            source,
            replacement,
            width=int(destination_size) * 8,
        )
        if not proven:
            self._shadow_structural_refused = True
        return proven

    def _get_shadow_replacement(self, candidate: _ShadowBindingCandidate) -> Any | None:
        """Use the native emitter without mutating its cached live pattern."""

        repl_pattern = self.REPLACEMENT_PATTERN
        if repl_pattern is None:
            return None
        try:
            replacement = repl_pattern.clone()
        except Exception:
            return None
        try:
            bindings = self._shadow_binding_context(candidate)
        except Exception:
            return None
        if not replacement.update_leafs_mop(bindings):
            return None
        if not self._materialize_replacement_constants(replacement, bindings):
            return None
        try:
            return replacement.create_minsn(bindings.ea, bindings.dst_mop)
        except AstEvaluationException:
            return None

    @staticmethod
    def _shadow_binding_context(candidate: Any) -> AstNode:
        """Materialize structural bindings as the active AST runtime's node type.

        The Cython ``update_leafs_mop`` entry point has an exact ``AstNode``
        signature, unlike the portable implementation's duck-typed path.  The
        proof-only shadow candidate and non-mutating binding proxy must
        therefore be copied into an otherwise empty active AST node before they
        cross that boundary.  Cython bindings expose direct ``MopSnapshot``
        values, so those values are wrapped in the leaf carrier expected by
        ``AstLeaf.update_leafs_mop``; native AstLeaf/MatchBinding values retain
        their original identities.
        """

        leafs_by_name = getattr(candidate, "leafs_by_name", None)
        if not isinstance(leafs_by_name, Mapping):
            raise TypeError("binding candidate must expose a leafs_by_name mapping")

        bindings = AstNode()
        bindings.leafs_by_name = {
            name: value
            if hasattr(value, "mop")
            else _BindingMopCarrier(value)
            for name, value in leafs_by_name.items()
        }
        bindings.ea = getattr(candidate, "ea", None)
        bindings.dst_mop = getattr(candidate, "dst_mop", None)
        bindings.is_candidate_ok = True
        return bindings

    def _publish_provider_outcome(self, outcome: MbaProviderOutcome) -> None:
        self._last_provider_outcome = outcome
        if not self._provider_outcome_capture_enabled():
            return
        history = getattr(self, "provider_outcome_history", None)
        if not isinstance(history, ProviderOutcomeHistory):
            history = ProviderOutcomeHistory[MbaProviderOutcome]()
            self.provider_outcome_history = history
        attempt_index = getattr(self, "_attempt_outcome_index", None)
        if attempt_index is None:
            self._attempt_outcome_index = history.append(outcome)
        else:
            history.replace(attempt_index, outcome)

    def _attempt_elapsed_ms(self) -> float:
        if self._attempt_started is None:
            return 0.0
        return max(0.0, (time.monotonic() - self._attempt_started) * 1000.0)

    def _catalogue_provenance(self) -> tuple[str, tuple[str, ...]]:
        return (
            str(getattr(self.rule, "CANONICAL_NAME", self.name)),
            tuple(str(item) for item in getattr(self.rule, "ALIASES", ())),
        )

    @staticmethod
    def _ast_cost(ast: Any) -> tuple[int, int] | None:
        """Return the portable (operator, total node) cost for an AST shape."""

        if ast is None:
            return None
        try:
            if not ast.is_node():
                return (0, 1)
            children = (getattr(ast, "left", None), getattr(ast, "right", None))
            child_costs = tuple(
                IDAPatternAdapter._ast_cost(child)
                for child in children
                if child is not None
            )
            if any(cost is None for cost in child_costs):
                return None
            return (
                1 + sum(cost[0] for cost in child_costs if cost is not None),
                1 + sum(cost[1] for cost in child_costs if cost is not None),
            )
        except Exception:
            return None

    def _profile_for_ast(self, ast: Any):
        """Return the exact native profile used to publish provider telemetry."""

        destination_size = self._attempt_destination_size
        if destination_size is None:
            return None
        try:
            from d810.backends.mba.hexrays_island import lower_hexrays_island

            lowering = lower_hexrays_island(
                ast,
                destination_size=int(destination_size),
            )
            return lowering.profile if lowering.term is not None else None
        except Exception:
            return None

    def _profile_fingerprint(self, ast: Any) -> str | None:
        """Return an exact native boundary fingerprint, never a guessed fallback."""

        profile = self._profile_for_ast(ast)
        return None if profile is None else profile.fingerprint

    @staticmethod
    def _native_profile_metadata(profile) -> dict[str, object]:
        from d810.mba.native_corpus_capture import native_profile_metadata

        return {"native_profile": native_profile_metadata(profile)}

    def _record_catalogue_success(self, input_ast: Any, replacement_ast: Any) -> None:
        """Publish a successful direct-rule attempt without adding generic Z3."""

        canonical_source, aliases = self._catalogue_provenance()
        elapsed_ms = self._attempt_elapsed_ms()
        profile = self._profile_for_ast(input_ast)
        fingerprint = (
            profile.fingerprint
            if profile is not None
            else self._profile_fingerprint(input_ast)
        )
        metadata = {
            "rule_name": self.name,
            "canonical_source": canonical_source,
        }
        if profile is not None:
            metadata.update(self._native_profile_metadata(profile))
        structural_selection = bool(
            getattr(self, "_structural_selection_active", False)
        )
        if structural_selection:
            metadata["structural_dispatch"] = {
                "bucket_size": self._structural_dispatch_bucket_size,
                "attempted_rule_count": self._structural_dispatch_attempt_count,
            }
        else:
            metadata["shadow"] = self._shadow_metadata(legacy_match=True)
        if fingerprint is None:
            self._publish_provider_outcome(
                MbaProviderOutcome(
                    provider=MbaProviderKind.CATALOGUE,
                    status=ProviderOutcomeStatus.RECONSTRUCTION_FAILED,
                    fingerprint="profile_unavailable",
                    input_cost=self._ast_cost(input_ast),
                    output_cost=self._ast_cost(replacement_ast),
                    elapsed_ms=elapsed_ms,
                    source_provenance=(canonical_source, *aliases),
                    refusal_reason="profile_unavailable",
                    metadata=metadata,
                    matcher=self._matcher_metadata(),
                )
            )
            if not structural_selection:
                self._record_shadow_parity(legacy_match=True)
            return
        self._publish_provider_outcome(
            MbaProviderOutcome(
                provider=MbaProviderKind.CATALOGUE,
                status=ProviderOutcomeStatus.IMPROVED,
                fingerprint=fingerprint,
                input_cost=self._ast_cost(input_ast),
                output_cost=self._ast_cost(replacement_ast),
                proof_verdict=None,
                elapsed_ms=elapsed_ms,
                source_provenance=(canonical_source, *aliases),
                metadata=metadata,
                matcher=self._matcher_metadata(),
            )
        )
        if not structural_selection and self._shadow_observation_enabled():
            self._record_shadow_parity(legacy_match=True)

    def _finalize_candidate_outcome(
        self, *, accepted: bool, reason: str | None = None
    ) -> None:
        """Let the outer mutation owner decide whether a candidate was applied."""

        outcome = self._last_provider_outcome
        if outcome is None or outcome.status is not ProviderOutcomeStatus.IMPROVED:
            return
        metadata = dict(outcome.metadata or {})
        metadata["mutation_outcome"] = "accepted" if accepted else "rejected"
        if reason is not None:
            metadata["mutation_rejection_reason"] = reason
        self._publish_provider_outcome(
            replace(
                outcome,
                status=(
                    ProviderOutcomeStatus.APPLIED
                    if accepted
                    else ProviderOutcomeStatus.IMPROVED
                ),
                refusal_reason=None if accepted else reason,
                metadata=metadata,
            )
        )

    def record_mutation_accepted(self) -> None:
        """Upgrade a candidate only after the optinsn owner accepts its swap."""

        self._finalize_candidate_outcome(accepted=True)

    def record_mutation_rejected(self, reason: str) -> None:
        """Keep an outer-vetoed candidate observable but non-applied."""

        self._finalize_candidate_outcome(accepted=False, reason=reason)

    def _record_catalogue_nonmatch(self) -> None:
        """Publish a direct-rule miss even though no rule-fired stat exists."""

        if self._last_provider_outcome is not None:
            return
        capture_enabled = self._provider_outcome_capture_enabled()
        shadow_enabled = self._shadow_observation_enabled()
        if not capture_enabled and not shadow_enabled:
            return
        if not capture_enabled:
            self._record_shadow_parity(
                legacy_match=bool(getattr(self, "_legacy_match_observed", False))
            )
            return
        canonical_source, aliases = self._catalogue_provenance()
        input_ast = self._attempt_input_ast
        profile = self._profile_for_ast(input_ast)
        fingerprint = (
            profile.fingerprint
            if profile is not None
            else self._profile_fingerprint(input_ast)
        )
        legacy_match = bool(getattr(self, "_legacy_match_observed", False))
        structural_selection = bool(
            getattr(self, "_structural_selection_active", False)
        )
        metadata: dict[str, object] = {}
        if profile is not None:
            metadata.update(self._native_profile_metadata(profile))
        if structural_selection:
            metadata["structural_dispatch"] = {
                "bucket_size": self._structural_dispatch_bucket_size,
                "attempted_rule_count": self._structural_dispatch_attempt_count,
            }
        else:
            metadata["shadow"] = self._shadow_metadata(legacy_match=legacy_match)
        if fingerprint is None:
            self._publish_provider_outcome(
                MbaProviderOutcome(
                    provider=MbaProviderKind.CATALOGUE,
                    status=ProviderOutcomeStatus.RECONSTRUCTION_FAILED,
                    fingerprint="profile_unavailable",
                    input_cost=self._ast_cost(input_ast),
                    elapsed_ms=self._attempt_elapsed_ms(),
                    source_provenance=(canonical_source, *aliases),
                    refusal_reason="profile_unavailable",
                    metadata=metadata,
                    matcher=self._matcher_metadata(),
                )
            )
            if not structural_selection and shadow_enabled:
                self._record_shadow_parity(legacy_match=legacy_match)
            return
        self._publish_provider_outcome(
            MbaProviderOutcome(
                provider=MbaProviderKind.CATALOGUE,
                status=ProviderOutcomeStatus.UNCHANGED,
                fingerprint=fingerprint,
                input_cost=self._ast_cost(input_ast),
                elapsed_ms=self._attempt_elapsed_ms(),
                source_provenance=(canonical_source, *aliases),
                refusal_reason="no_match",
                metadata=metadata,
                matcher=self._matcher_metadata(),
            )
        )
        if not structural_selection and shadow_enabled:
            self._record_shadow_parity(legacy_match=legacy_match)

    def record_attempt_error(self, exc: RuntimeError) -> None:
        """Finalize a caught pattern-engine failure as an explicit error row."""

        if not self._provider_outcome_capture_enabled():
            return

        canonical_source, aliases = self._catalogue_provenance()
        input_ast = self._attempt_input_ast
        profile = self._profile_for_ast(input_ast)
        fingerprint = (
            profile.fingerprint
            if profile is not None
            else self._profile_fingerprint(input_ast) or "profile_unavailable"
        )
        structural_selection = bool(
            getattr(self, "_structural_selection_active", False)
        )
        metadata: dict[str, object] = {
            "error_class": type(exc).__name__,
            "error_message": str(exc),
        }
        if profile is not None:
            metadata.update(self._native_profile_metadata(profile))
        if structural_selection:
            metadata["structural_dispatch"] = {
                "bucket_size": self._structural_dispatch_bucket_size,
                "attempted_rule_count": self._structural_dispatch_attempt_count,
            }
        else:
            metadata["shadow"] = self._shadow_metadata(
                legacy_match=bool(getattr(self, "_legacy_match_observed", False))
            )
        self._publish_provider_outcome(
            MbaProviderOutcome(
                provider=MbaProviderKind.CATALOGUE,
                status=ProviderOutcomeStatus.ERROR,
                fingerprint=fingerprint,
                input_cost=self._ast_cost(input_ast),
                elapsed_ms=self._attempt_elapsed_ms(),
                source_provenance=(canonical_source, *aliases),
                refusal_reason=type(exc).__name__,
                metadata=metadata,
                matcher=self._matcher_metadata(),
            )
        )
        if not structural_selection and self._shadow_observation_enabled():
            self._record_shadow_parity(
                legacy_match=bool(getattr(self, "_legacy_match_observed", False))
            )

    def record_bound_replacement_outcome(self, replacement_ast: Any) -> None:
        """Publish the nomut path's success using its bound native input AST."""

        self._record_catalogue_success(self._attempt_input_ast, replacement_ast)

    def provider_outcomes(self) -> tuple[MbaProviderOutcome, ...]:
        """Return one final outcome for each direct-catalogue attempt."""

        return self.provider_outcome_history.outcomes()

    def provider_outcome_cursor(self) -> int:
        """Return a capture cursor for the bounded direct-catalogue history."""

        return self.provider_outcome_history.cursor

    def provider_outcomes_since(self, cursor: int) -> tuple[MbaProviderOutcome, ...]:
        """Return one exact retained capture delta or fail closed on eviction."""

        return self.provider_outcome_history.since(cursor)

    # ==========================================================================
    # Properties delegated to the underlying rule
    # ==========================================================================

    @property
    def name(self) -> str:
        """Return the rule name."""
        return self.rule.name

    @property
    def description(self) -> str:
        """Return the rule description."""
        return self.rule.description

    @property
    def maturities(self) -> list:
        """Return the maturities this rule applies to."""
        return getattr(self.rule, "maturities", [])

    @maturities.setter
    def maturities(self, value: list) -> None:
        """Set the maturities this rule applies to."""
        self.rule.maturities = value

    @property
    def config(self) -> dict:
        """Return the rule configuration."""
        return getattr(self.rule, "config", {})

    # ==========================================================================
    # IDA Pattern Matching Interface
    # ==========================================================================

    @property
    def pattern_candidates(self) -> List[AstNode]:
        """Get pattern candidates as AstNodes (lazy conversion from DSL).

        This property lazily converts the DSL SymbolicExpression to AstNode
        only when accessed in IDA context.

        Snapshot-selected certified DSL rules register exactly their declared
        base pattern and match commutation structurally.  The temporary
        D810_LEGACY_DSL_PERMUTATIONS=1 rollback preserves the old generated
        variants for one release.  Non-snapshot adapters retain the legacy
        generator unchanged.
        """
        if self._pattern_candidates_cache is None:
            pattern = self.rule.pattern
            if pattern is None:
                self._pattern_candidates_cache = []
                return self._pattern_candidates_cache

            # Structural selection removes generated commutations only for
            # the configuration-selected certified DSL catalogue.  All other
            # adapters keep the historical path.
            if (
                self.uses_structural_matching
                or not self._generate_commutative_permutations
                or not getattr(self.rule, "GENERATE_COMMUTATIVE_PERMUTATIONS", True)
            ):
                permutations = [pattern]
            else:
                permutations = _generate_commutative_permutations(pattern)
            logger.debug(
                "Rule %s: Generated %d commutative permutations",
                self.name,
                len(permutations),
            )

            # Commutative permutations are correct BY CONSTRUCTION -- they are
            # generated from each operation's commutativity, so there is
            # nothing to verify. An egglog equivalence check used to run here
            # and was removed: it cost 30+ seconds at startup across 170+ rules
            # to confirm what the generator already guarantees.
            candidates = []
            for expr in permutations:
                try:
                    ast_node = self._visitor.visit(expr)
                    if ast_node is not None:
                        candidates.append(ast_node)
                except Exception as e:
                    logger.debug("Failed to convert pattern to AstNode: %s", e)

            self._pattern_candidates_cache = candidates
        return self._pattern_candidates_cache

    @property
    def PATTERN(self) -> Optional[AstNode]:
        """Get the pattern as an AstNode (PatternMatchingRule interface)."""
        pattern = self.rule.pattern
        if pattern is not None:
            return self._visitor.visit(pattern)
        return None

    @property
    def REPLACEMENT_PATTERN(self) -> Optional[AstNode]:
        """Get the replacement as an AstNode (PatternMatchingRule interface).

        Cached for performance - conversion only happens once.
        """
        if self._replacement_pattern_cache is None:
            replacement = self.rule.replacement
            if replacement is not None:
                self._replacement_pattern_cache = self._visitor.visit(replacement)
        return self._replacement_pattern_cache

    def get_valid_candidates(self, instruction, stop_early: bool = True) -> list:
        """Match the instruction against this rule's patterns.

        Args:
            instruction: The IDA minsn_t instruction to match.
            stop_early: If True, return after first match.

        Returns:
            List of matched candidate AstNodes.
        """
        valid_candidates = []
        tmp = minsn_to_ast(instruction)
        if tmp is None:
            return []

        for candidate_pattern in self.pattern_candidates:
            if not candidate_pattern:
                continue
            # Use a read-only check first for structural matching (no mops copied)
            if not candidate_pattern.check_pattern_and_copy_mops(tmp, read_only=True):
                continue
            # Create a mutable copy and populate mops
            mutable_candidate = candidate_pattern.clone()
            if not mutable_candidate.check_pattern_and_copy_mops(tmp):
                continue
            # Check constraints AFTER mops are populated
            # This ensures constraint checks have access to the matched mops
            if not self._check_candidate(mutable_candidate):
                continue
            self.record_legacy_match_bindings(mutable_candidate, tmp)
            valid_candidates.append(mutable_candidate)
            if stop_early:
                return valid_candidates
        return valid_candidates

    def get_replacement(self, candidate) -> Optional[Any]:
        """Create a replacement instruction from a matched candidate.

        Args:
            candidate: The matched AstNode or AstLeaf candidate.

        Returns:
            A new minsn_t instruction, or None if replacement failed.
        """
        repl_pat = self.REPLACEMENT_PATTERN
        if not repl_pat:
            logger.debug(f"No replacement pattern for rule {self.name}")
            return None

        candidate_for_update = candidate

        # Handle AstLeaf candidates specially - they don't have leafs_by_name
        if isinstance(candidate, AstLeafProtocol):
            candidate_for_update = _LeafWrapper(candidate)
        elif not isinstance(candidate, AstNode):
            try:
                candidate_for_update = self._shadow_binding_context(candidate)
            except (AttributeError, TypeError, ValueError) as exc:
                logger.debug(
                    "Failed to materialize replacement bindings for rule %s: %s",
                    self.name,
                    exc,
                )
                return None

        is_ok = repl_pat.update_leafs_mop(candidate_for_update)

        if not is_ok:
            logger.debug(f"Failed to update leaf mops for rule {self.name}")
            return None

        if not candidate_for_update.ea:
            logger.debug(f"No EA for candidate in rule {self.name}")
            return None

        if not self._materialize_replacement_constants(
            repl_pat, candidate_for_update
        ):
            logger.debug(
                "Failed to materialize replacement constants for rule %s",
                self.name,
            )
            return None

        try:
            new_ins = repl_pat.create_minsn(
                candidate_for_update.ea, candidate_for_update.dst_mop
            )
        except AstEvaluationException as exc:
            logger.debug(
                "Replacement creation failed for rule %s at 0x%x: %s",
                self.name,
                candidate.ea,
                exc,
            )
            return None
        return new_ins

    def _materialize_replacement_constants(self, repl_pat, candidate) -> bool:
        """Ensure computed AstConstant leaves have concrete mops before emission."""
        try:
            leafs = repl_pat.get_leaf_list()
        except Exception:
            return True

        candidate_leafs = getattr(candidate, "leafs_by_name", {}) or {}
        dst_mop = getattr(candidate, "dst_mop", None)

        for leaf in leafs:
            if not isinstance(leaf, AstConstantProtocol):
                continue
            if getattr(leaf, "mop", None) is not None:
                continue

            value = getattr(leaf, "value", None)
            size = getattr(leaf, "expected_size", None)

            source_leaf = candidate_leafs.get(getattr(leaf, "name", None))
            if source_leaf is not None:
                source_mop = getattr(source_leaf, "mop", None)
                if source_mop is not None and source_mop.t == ida_hexrays.mop_n:
                    leaf.mop = MopSnapshot.from_mop(source_mop)
                    if hasattr(leaf, "expected_value"):
                        leaf.expected_value = source_mop.nnn.value
                    if hasattr(leaf, "expected_size"):
                        leaf.expected_size = source_mop.size
                    continue
                if value is None:
                    value = getattr(source_leaf, "value", None)
                if value is None:
                    value = getattr(source_leaf, "expected_value", None)
                if size is None:
                    size = getattr(source_leaf, "expected_size", None)

            if value is None:
                return False

            if size is None:
                size = getattr(leaf, "dest_size", None)
            if size is None and dst_mop is not None:
                size = getattr(dst_mop, "size", None)
            if size is None or int(size) <= 0:
                size = 1

            cst_mop = ida_hexrays.mop_t()
            safe_make_number(cst_mop, int(value), int(size))
            leaf.mop = cst_mop
            if hasattr(leaf, "expected_value"):
                leaf.expected_value = int(value)
            if hasattr(leaf, "expected_size"):
                leaf.expected_size = int(size)

        return True

    def check_and_replace(self, blk, instruction) -> Optional[Any]:
        """Check if this rule matches and return a replacement instruction.

        This is the main entry point called by the optimizer system.

        Args:
            blk: The microcode block (mblock_t).
            instruction: The instruction to check (minsn_t).

        Returns:
            A new minsn_t if the rule matched, None otherwise.
        """
        self._reset_attempt_outcome(instruction)
        setattr(self.rule, "_current_blk", blk)
        setattr(self.rule, "_current_ins", instruction)
        try:
            valid_candidates = self.get_valid_candidates(instruction, stop_early=True)
            if len(valid_candidates) == 0:
                return None
            candidate = valid_candidates[0]
            new_instruction = self.get_replacement(candidate)
            if new_instruction is not None:
                self._record_catalogue_success(candidate, self.REPLACEMENT_PATTERN)
            return new_instruction
        finally:
            self._record_catalogue_nonmatch()
            setattr(self.rule, "_current_blk", None)
            setattr(self.rule, "_current_ins", None)

    def bind_match_context(self, blk, instruction) -> None:
        """Expose the current live match site to runtime-checked MBA rules.

        PatternOptimizer normally invokes rules through the pattern-storage
        path, which only passes ASTs into ``check_pattern_and_replace``.  Some
        backend-adapted MBA rules need the original instruction site for
        conservative local constant evaluation.  Keep that context on the
        adapter boundary so the pure rule model remains backend-agnostic.
        """
        self._reset_attempt_outcome(instruction)
        setattr(self.rule, "_current_blk", blk)
        setattr(self.rule, "_current_ins", instruction)
        setattr(
            self.rule,
            "_runtime_constant_evaluator",
            lambda mop, *, bits: self._eval_runtime_constant(
                mop, bits, blk, instruction
            ),
        )

    def clear_match_context(self) -> None:
        """Clear live match-site state after a pattern-storage rule attempt."""
        self._record_catalogue_nonmatch()
        setattr(self.rule, "_current_blk", None)
        setattr(self.rule, "_current_ins", None)
        setattr(self.rule, "_runtime_constant_evaluator", None)
        self._attempt_started = None
        self._attempt_destination_size = None
        self._attempt_input_ast = None

    @staticmethod
    def _eval_runtime_constant(mop, bits: int, blk, instruction) -> int | None:
        if hasattr(mop, "to_mop"):
            try:
                mop = mop.to_mop()
            except Exception:
                return None
        try:
            from d810.evaluator.hexrays_microcode.constant_eval import eval_mop

            return eval_mop(mop, bits, blk=blk, ins=instruction)
        except Exception:
            return None

    def check_pattern_and_replace(self, candidate_pattern, test_ast) -> Optional[Any]:
        """Check if this rule matches a pattern and return a replacement.

        This method is used by PatternOptimizer's pattern storage lookup system.

        Args:
            candidate_pattern: A candidate AstNode pattern from the pattern storage.
            test_ast: The AstNode converted from the microcode instruction.

        Returns:
            A new minsn_t if the rule matched, None otherwise.
        """
        # First, check if the pattern matches the test AST
        if not candidate_pattern.check_pattern_and_copy_mops(test_ast):
            return None

        # Then check candidate-level constraints
        if not self._check_candidate(candidate_pattern):
            return None
        self.record_legacy_match_bindings(candidate_pattern, test_ast)

        # Finally, create the replacement instruction
        new_instruction = self.get_replacement(candidate_pattern)
        if new_instruction is not None:
            self._record_catalogue_success(test_ast, self.REPLACEMENT_PATTERN)
        return new_instruction

    def execution_metadata(self) -> dict[str, object]:
        """Expose direct-catalogue outcome data for the existing statistics hook."""

        outcome = self._last_provider_outcome
        return {} if outcome is None else {"mba_provider_outcome": outcome.to_dict()}

    def check_candidate(self, candidate) -> bool:
        """Public interface for nomut matching path constraint checking.

        This method is called by the nomut hot path in handler.py when the
        resolved ``nomut_matching`` runtime setting is enabled.  That setting
        is environment-aware: an explicit ``D810_NOMUT_MATCHING`` value takes
        precedence over the persisted Developer preference.  It delegates to
        ``_check_candidate()``.

        Args:
            candidate: An AstNode or BindingsProxy that matched the pattern

        Returns:
            True if all constraints are satisfied, False otherwise
        """
        return self._check_candidate(candidate)

    # ==========================================================================
    # Internal constraint checking (delegates to rule)
    # ==========================================================================

    def _check_candidate(self, candidate) -> bool:
        """Check if a candidate AstNode matches this rule's constraints.

        Delegates to the underlying rule's check_candidate method if available,
        otherwise performs basic constraint checking.

        Args:
            candidate: An AstNode that structurally matches PATTERN

        Returns:
            True if all constraints are satisfied, False otherwise
        """
        # If rule has check_candidate, use it
        if hasattr(self.rule, "check_candidate"):
            return self.rule.check_candidate(candidate)

        # Fallback: check runtime constraints directly
        return self._check_runtime_constraints(candidate)

    def _check_runtime_constraints(self, candidate) -> bool:
        """Check runtime constraints against a matched candidate.

        Args:
            candidate: The matched AstNode with variable bindings.

        Returns:
            True if all constraints pass, False otherwise.
        """
        constraints = getattr(self.rule, "CONSTRAINTS", [])
        if not constraints:
            return True

        # Build match context from candidate's matched variables
        # AstNode stores matched leaves in leafs_by_name after pattern matching
        match_context = {}
        if hasattr(candidate, "leafs_by_name") and candidate.leafs_by_name:
            match_context = candidate.leafs_by_name
        elif hasattr(candidate, "mop_dict"):
            match_context = candidate.mop_dict
        elif hasattr(candidate, "get_z3_vars"):
            match_context = candidate.get_z3_vars({})

        # Add candidate itself to context
        match_context["_candidate"] = candidate

        # Check each constraint
        for constraint in constraints:
            try:
                # Check if this is a ConstraintExpr
                if is_constraint_expr(constraint):
                    if not constraint.check(match_context):
                        return False
                elif callable(constraint):
                    if not constraint(match_context):
                        return False
            except Exception as e:
                logger.debug(f"Constraint check failed for {self.name}: {e}")
                return False

        return True

    # ==========================================================================
    # Configuration interface (required by d810 optimizer system)
    # ==========================================================================

    def configure(self, kwargs: Dict[str, Any]) -> None:
        """Configure this rule with options from a JSON config.

        Args:
            kwargs: Configuration dictionary from the JSON project file.
        """
        generate_permutations = (kwargs or {}).get(
            "generate_commutative_permutations", True
        )
        if type(generate_permutations) is not bool:
            raise ValueError("generate_commutative_permutations must be boolean")
        if self._generate_commutative_permutations != generate_permutations:
            self._pattern_candidates_cache = None
        self._generate_commutative_permutations = generate_permutations
        if hasattr(self.rule, "configure"):
            self.rule.configure(kwargs)

    def set_log_dir(self, log_dir: str) -> None:
        """Set the log directory for this rule.

        Args:
            log_dir: Path to the log directory.
        """
        if hasattr(self.rule, "set_log_dir"):
            self.rule.set_log_dir(log_dir)


def adapt_rules(rules: List[VerifiableRule]) -> List[IDAPatternAdapter]:
    """Wrap a list of rules with IDAPatternAdapter for IDA integration.

    Args:
        rules: List of VerifiableRule instances.

    Returns:
        List of IDAPatternAdapter instances wrapping the rules.

    Example:
        >>> from d810.mba.rules import VerifiableRule
        >>> from d810.backends.mba.ida import adapt_rules
        >>>
        >>> rule_instances = VerifiableRule.instantiate_all()
        >>> ida_rules = adapt_rules(rule_instances)
    """
    return [IDAPatternAdapter(rule) for rule in rules]


def attach_selected_certified_catalogue_snapshot(
    adapters: tuple[IDAPatternAdapter, ...] | List[IDAPatternAdapter],
    *,
    parity_certificate_path: Path | None = None,
    parity_expectation=None,
    runtime_mode: str | None = None,
):
    """Freeze the already-selected direct DSL rules outside the optinsn path."""

    from d810.mba.certified_catalogue import (
        ShadowMatcherParityLedger,
        build_certified_catalogue_snapshot,
        load_structural_matcher_parity_certificate,
    )
    from d810.backends.mba.egglog_structural_rules import (
        compile_all_fixed_rotate_rules,
    )

    selected = tuple(adapters)
    rules = tuple(adapter.rule for adapter in selected)
    enabled_families = tuple(
        dict.fromkeys(type(rule).__module__.rsplit(".", 1)[-1] for rule in rules)
    )
    snapshot = build_certified_catalogue_snapshot(
        rules,
        compiler_version="verifiable-rule-dsl-v1",
        enabled_families=enabled_families,
        structural_rules=tuple(
            receipt.compiled_rule
            for receipt in compile_all_fixed_rotate_rules()
            if receipt.compiled_rule is not None
        ),
    )
    parity_certificate = None
    if parity_certificate_path is not None:
        try:
            parity_certificate = load_structural_matcher_parity_certificate(
                parity_certificate_path
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            logger.warning(
                "Structural matcher parity certificate unavailable (%s): %s",
                parity_certificate_path,
                exc,
            )
    if runtime_mode not in {"python", "cython"}:
        runtime_mode = None
    ledger = ShadowMatcherParityLedger()
    # ``build_certified_catalogue_snapshot`` can return a cached immutable
    # view containing earlier rule instances. The selected input order is the
    # certified declaration order used for that fingerprint, so attach by
    # position rather than transient Python object identity.
    for rule_id, adapter in enumerate(selected):
        adapter.attach_certified_catalogue_snapshot(
            snapshot,
            rule_id,
            ledger,
            parity_certificate,
            parity_expectation,
            runtime_mode,
        )
    return snapshot, ledger


__all__ = [
    "IDANodeVisitor",
    "IDAPatternAdapter",
    "adapt_rules",
    "attach_selected_certified_catalogue_snapshot",
]
