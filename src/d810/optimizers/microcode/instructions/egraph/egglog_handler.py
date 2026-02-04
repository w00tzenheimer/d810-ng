"""E-Graph based instruction optimizer using egglog equality saturation.

This optimizer uses egglog (a Rust-based e-graph library with Python bindings)
to simplify MBA (Mixed Boolean-Arithmetic) expressions via equality saturation.

Key benefits over traditional pattern matching:
1. O(1) rules instead of O(N!) pattern variations
2. Automatic commutativity handling via rewrite rules
3. More principled mathematical foundation
4. Extensible with associativity, distributivity, etc.

Requirements:
    pip install egglog cloudpickle

Usage:
    In hexrays_hooks.py, add:

    from d810.optimizers.microcode.instructions.egraph import EgglogOptimizer

    self.add_optimizer(
        EgglogOptimizer(
            DEFAULT_OPTIMIZATION_PATTERN_MATURITIES,
            stats=self.stats,
        )
    )
"""

from __future__ import annotations

import typing

import ida_hexrays

from d810.core import getLogger
from d810.expr.ast import AstNode, minsn_to_ast
from d810.hexrays.hexrays_formatters import format_minsn_t
from d810.optimizers.microcode.instructions.handler import InstructionOptimizer

if typing.TYPE_CHECKING:
    from d810.core import OptimizationStatistics

# Import egglog backend
from d810.mba.backends.egglog_backend import EGGLOG_AVAILABLE

if EGGLOG_AVAILABLE:
    from d810.mba.backends.egglog_backend import (
        AstToBitExprConverter,
        BitExpr,
        MBAEGraph,
    )

optimizer_logger = getLogger("D810.optimizer")


class EgglogOptimizer(InstructionOptimizer):
    """IDA microcode optimizer using egglog equality saturation.

    This optimizer replaces complex MBA expressions with their simplified
    equivalents using e-graph based equivalence checking. It handles
    commutativity automatically via rewrite rules, eliminating the need
    for explicit commuted rule variants.

    Example equivalences it can detect:
    - (a & b) + (a ^ b) => a | b
    - (a ^ b) + (a & b) => a | b  (commuted - handled automatically!)
    - (a | b) - (a ^ b) => a & y
    - (a | b) - (a & y) => a ^ b
    - (a ^ b) ^ b => a  (XOR cancellation)

    Performance Note:
        The e-graph is cached and reused across instructions within a single
        decompilation pass. This is much faster than creating a new e-graph
        per instruction, but the graph grows over time. Call reset_egraph()
        between decompilations if needed.
    """

    RULE_CLASSES = []  # No traditional rules - uses e-graph rewriting

    # Cached e-graph instance (shared across all instances for performance)
    _cached_egraph: typing.ClassVar["MBAEGraph | None"] = None
    _cached_max_iterations: typing.ClassVar[int] = 10

    def __init__(
        self,
        maturities: list[int],
        stats: "OptimizationStatistics",
        log_dir=None,
        max_iterations: int = 10,
    ):
        """Initialize the egglog optimizer.

        Args:
            maturities: List of maturity levels to operate at.
            stats: Statistics tracking object.
            log_dir: Optional log directory.
            max_iterations: Maximum saturation iterations per expression.
        """
        super().__init__(maturities, stats, log_dir=log_dir)
        self.max_iterations = max_iterations
        self._enabled = EGGLOG_AVAILABLE

        if not EGGLOG_AVAILABLE:
            optimizer_logger.warning(
                "[EgglogOptimizer] egglog not installed - optimizer disabled. "
                "Install with: pip install egglog cloudpickle"
            )
            
    @classmethod
    def _get_egraph(cls, max_iterations: int = 10) -> "MBAEGraph":
        """Get or create the cached MBAEGraph instance.

        This caches the e-graph with all MBA rewrite rules registered.
        Reusing the e-graph avoids the expensive rule registration on
        every instruction, providing a significant speedup.

        Args:
            max_iterations: Maximum saturation iterations.

        Returns:
            Cached MBAEGraph instance.
        """
        if cls._cached_egraph is None or cls._cached_max_iterations != max_iterations:
            cls._cached_egraph = MBAEGraph(max_iterations=max_iterations)
            cls._cached_max_iterations = max_iterations
        return cls._cached_egraph

    @classmethod
    def reset_egraph(cls):
        """Reset the cached e-graph.

        Call this between decompilations to prevent the e-graph from
        growing too large. The next call to _get_egraph() will create
        a fresh e-graph with all rules registered.
        """
        cls._cached_egraph = None

    def get_optimized_instruction(
        self,
        blk: ida_hexrays.mblock_t,
        ins: ida_hexrays.minsn_t,
    ) -> ida_hexrays.minsn_t | None:
        """Try to optimize an instruction using egglog equality saturation.

        Args:
            blk: The basic block containing the instruction.
            ins: The instruction to optimize.

        Returns:
            Optimized instruction, or None if no optimization found.
        """
        if not self._enabled:
            return None

        # Check maturity
        if blk is not None:
            self.cur_maturity = blk.mba.maturity
        if self.cur_maturity not in self.maturities:
            return None

        # Only process relevant opcodes
        if ins.opcode not in {
            ida_hexrays.m_add,
            ida_hexrays.m_sub,
            ida_hexrays.m_and,
            ida_hexrays.m_or,
            ida_hexrays.m_xor,
        }:
            return None

        # Convert instruction to AST
        ast = minsn_to_ast(ins)
        if ast is None:
            return None

        # Try to simplify using e-graph
        simplified = self._try_simplify(ast, ins)
        if simplified is None:
            return None

        # Create new instruction from simplified AST
        new_ins = self._create_instruction(simplified, ins)
        if new_ins is None:
            return None

        if optimizer_logger.info_on:
            optimizer_logger.info(
                "[EgglogOptimizer] Simplified in maturity %s:",
                self.cur_maturity,
            )
            optimizer_logger.info("  orig: %s", format_minsn_t(ins))
            optimizer_logger.info("  new : %s", format_minsn_t(new_ins))

        # Record statistics
        if self.stats is not None:
            self.stats.record_rule_fired(
                rule=None,  # E-graph doesn't use named rules
                rule_name="EgglogSimplification",
                optimizer=self.name,
                maturity=self.cur_maturity,
            )

        return new_ins

    def _try_simplify(self, ast, original_ins) -> AstNode | None:
        """Try to simplify an AST using egglog equality saturation.

        Args:
            ast: The AST to simplify.
            original_ins: Original instruction (for size info).

        Returns:
            Simplified AstNode, or None if no simplification found.
        """
        # Convert AST to BitExpr
        converter = AstToBitExprConverter()
        bit_expr = converter.convert(ast)
        if bit_expr is None:
            return None

        # Get leaf mapping for reconstruction
        leaf_mapping = converter.get_leaf_mapping()

        # Only handle 2-variable expressions for now
        if len(leaf_mapping) != 2:
            return None

        # Get cached e-graph (much faster than creating new one each time)
        egraph = self._get_egraph(self.max_iterations)
        egraph.add_expression("input", bit_expr)

        # Find simplification
        return self._find_simplification(egraph, bit_expr, leaf_mapping)

    def _find_simplification(
        self,
        egraph: MBAEGraph,
        original: "BitExpr",
        leaf_mapping: dict[str, typing.Any],
    ) -> AstNode | None:
        """Find a simpler equivalent expression.

        Args:
            egraph: The e-graph with rules registered.
            original: The original BitExpr.
            leaf_mapping: Mapping from variable names to AST leaves.

        Returns:
            Simplified AstNode, or None if no simplification found.
        """
        var_names = sorted(leaf_mapping.keys())
        x_name, y_name = var_names[0], var_names[1]
        x_leaf, y_leaf = leaf_mapping[x_name], leaf_mapping[y_name]

        x = BitExpr.var(x_name)
        y = BitExpr.var(y_name)

        # Candidate simplifications (from simple to complex)
        # We check simpler forms first
        candidates = [
            (x, None, "X"),
            (y, None, "Y"),
            (x | y, ida_hexrays.m_or, "OR"),
            (x & y, ida_hexrays.m_and, "AND"),
            (x ^ y, ida_hexrays.m_xor, "XOR"),
        ]

        # Add all candidates to e-graph
        for expr, _, _ in candidates:
            egraph.add_expression("candidate", expr)

        # Run saturation
        egraph.saturate()

        # Check each candidate for equivalence (simplest first)
        for expr, opcode, name in candidates:
            if egraph.check_equivalent(original, expr):
                # Found a simplification!
                if opcode is not None:
                    # Binary operation result
                    return AstNode(opcode, x_leaf.clone(), y_leaf.clone())
                elif name == "X":
                    return x_leaf.clone()
                elif name == "Y":
                    return y_leaf.clone()

        return None

    def _create_instruction(
        self,
        simplified_ast: AstNode,
        original_ins: ida_hexrays.minsn_t,
    ) -> ida_hexrays.minsn_t | None:
        """Create a new instruction from simplified AST.

        Args:
            simplified_ast: The simplified AST.
            original_ins: Original instruction (for size, EA, etc.).

        Returns:
            New minsn_t instruction, or None on failure.
        """
        try:
            # Create mop from simplified AST
            new_mop = simplified_ast.create_mop(original_ins.ea)
            if new_mop is None:
                return None

            # Create new instruction
            new_ins = ida_hexrays.minsn_t(original_ins.ea)
            new_ins.opcode = ida_hexrays.m_mov
            new_ins.l = new_mop
            new_ins.d = original_ins.d

            return new_ins

        except Exception as e:
            if optimizer_logger.debug_on:
                optimizer_logger.debug(
                    "[EgglogOptimizer] Failed to create instruction: %s", e
                )
            return None
