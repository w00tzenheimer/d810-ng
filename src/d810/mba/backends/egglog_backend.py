"""E-Graph based pattern matching backend using egglog.

This module provides an alternative pattern matching backend that uses
equality saturation via e-graphs instead of enumerating all commutative
variations upfront.

Benefits over the current ast_generator approach:
1. O(1) rules instead of O(N!) pattern variations
2. Automatic commutativity handling via rewrite rules
3. More principled mathematical foundation
4. Potential for more complex optimizations (associativity, etc.)

Usage:
    from d810.mba.backends.egglog_backend import EGraphOptimizer, check_egglog_available

    if check_egglog_available():
        optimizer = EGraphOptimizer()
        # optimizer integrates with IDA's minsn_t directly
"""

from __future__ import annotations

import logging
import typing

# Suppress extremely verbose egglog logging (generates 100k+ lines of INFO output)
# Must be done BEFORE importing egglog
logging.getLogger("egglog").setLevel(logging.WARNING)
logging.getLogger("egglog.egraph").setLevel(logging.WARNING)

try:
    from egglog import EGraph, Expr, StringLike, eq, i64Like, rewrite, vars_

    EGGLOG_AVAILABLE = True
except ImportError:
    EGGLOG_AVAILABLE = False


def check_egglog_available() -> bool:
    """Check if egglog is installed and available."""
    return EGGLOG_AVAILABLE


if EGGLOG_AVAILABLE:
    # Import ida_hexrays only when egglog is available and we're in IDA
    try:
        import ida_hexrays
    except ImportError:
        # Not in IDA environment - ida_hexrays not needed for pure pattern analysis
        ida_hexrays = None  # type: ignore

    # Define the expression class at module level (egglog v12+ API)
    class BitExpr(Expr):
        """Bitwise expression type for MBA patterns.

        Supports all common bitwise and arithmetic operations for
        Mixed Boolean-Arithmetic expression simplification.
        """

        def __init__(self, value: i64Like): ...

        @classmethod
        def var(cls, name: StringLike) -> "BitExpr":
            """Create a variable (leaf) expression."""
            ...

        # Arithmetic operations
        def __add__(self, other: "BitExpr") -> "BitExpr": ...
        def __sub__(self, other: "BitExpr") -> "BitExpr": ...
        def __mul__(self, other: "BitExpr") -> "BitExpr": ...
        def __neg__(self) -> "BitExpr": ...

        # Bitwise operations
        def __and__(self, other: "BitExpr") -> "BitExpr": ...
        def __or__(self, other: "BitExpr") -> "BitExpr": ...
        def __xor__(self, other: "BitExpr") -> "BitExpr": ...
        def __invert__(self) -> "BitExpr": ...

    class MBAEGraph:
        """E-Graph for Mixed Boolean-Arithmetic expression simplification.

        This class wraps egglog to provide MBA pattern matching using
        equality saturation instead of exhaustive pattern enumeration.

        Contains comprehensive MBA rules from:
        - Hacker's Delight (bitwise identities)
        - OLLVM deobfuscation patterns
        - De Morgan's laws
        - Basic identity/zero/idempotent rules
        """

        def __init__(self, max_iterations: int = 5):
            """Initialize the e-graph with MBA rewrite rules.

            Args:
                max_iterations: Maximum number of saturation iterations.
                               Reduced from 10 to 5 to prevent hangs on complex
                               flattened CFG patterns (OLLVM).
            """
            self.max_iterations = max_iterations
            self._setup_egraph()

        def _setup_egraph(self):
            """Initialize the e-graph with expression types and rewrite rules."""
            self.egraph = EGraph()

            # Create symbolic variables for rewrite rules
            x, y, z = vars_("x y z", BitExpr)

            # Store variables for later use
            self._rule_vars = (x, y, z)

            # Constants for rules
            zero = BitExpr(0)
            one = BitExpr(1)
            two = BitExpr(2)

            # ================================================================
            # COMMUTATIVITY RULES (fundamental)
            # ================================================================
            # These allow the e-graph to automatically handle operand order
            self.egraph.register(
                rewrite(x + y).to(y + x),
                rewrite(x & y).to(y & x),
                rewrite(x | y).to(y | x),
                rewrite(x ^ y).to(y ^ x),
                rewrite(x * y).to(y * x),
            )

            # ================================================================
            # IDENTITY RULES
            # ================================================================
            self.egraph.register(
                # x ^ 0 = x
                rewrite(x ^ zero).to(x),
                # x | 0 = x
                rewrite(x | zero).to(x),
                # x + 0 = x
                rewrite(x + zero).to(x),
                # x - 0 = x
                rewrite(x - zero).to(x),
                # x * 1 = x
                rewrite(x * one).to(x),
            )

            # ================================================================
            # ZERO/ANNIHILATOR RULES
            # ================================================================
            self.egraph.register(
                # x ^ x = 0
                rewrite(x ^ x).to(zero),
                # x & 0 = 0
                rewrite(x & zero).to(zero),
                # x * 0 = 0
                rewrite(x * zero).to(zero),
                # x - x = 0
                rewrite(x - x).to(zero),
            )

            # ================================================================
            # IDEMPOTENT RULES
            # ================================================================
            self.egraph.register(
                # x | x = x
                rewrite(x | x).to(x),
                # x & x = x
                rewrite(x & x).to(x),
            )

            # ================================================================
            # INVOLUTION RULES (double operations cancel)
            # ================================================================
            self.egraph.register(
                # ~(~x) => x (double bitwise negation)
                rewrite(~~x).to(x),
                # -(-x) => x (double arithmetic negation)
                rewrite(-(-x)).to(x),
            )

            # ================================================================
            # XOR MBA RULES (Hacker's Delight)
            # ================================================================
            self.egraph.register(
                # Xor_HackersDelightRule_1: (x | y) - (x & y) => x ^ y
                rewrite((x | y) - (x & y)).to(x ^ y),
                # Xor_HackersDelightRule_2: 2*(x | y) - (x + y) => x ^ y
                rewrite(two * (x | y) - (x + y)).to(x ^ y),
                # Xor_HackersDelightRule_3: (x + y) - 2*(x & y) => x ^ y
                rewrite((x + y) - two * (x & y)).to(x ^ y),
                # Xor_HackersDelightRule_5: x - (2*(x & y) - y) => x ^ y
                rewrite(x - (two * (x & y) - y)).to(x ^ y),
                # Xor_FactorRule_1: (x & ~y) | (~x & y) => x ^ y
                rewrite((x & (~y)) | ((~x) & y)).to(x ^ y),
                # Xor_FactorRule_2: (~x & y) ^ (x & ~y) => x ^ y
                rewrite(((~x) & y) ^ (x & (~y))).to(x ^ y),
                # Xor_FactorRule_3: (x & y) ^ (x | y) => x ^ y
                rewrite((x & y) ^ (x | y)).to(x ^ y),
                # XOR cancellation: (x ^ y) ^ y => x
                rewrite((x ^ y) ^ y).to(x),
            )

            # ================================================================
            # OR MBA RULES (Hacker's Delight)
            # ================================================================
            self.egraph.register(
                # Or_MbaRule_1: (x & y) + (x ^ y) => x | y
                rewrite((x & y) + (x ^ y)).to(x | y),
                # Or_HackersDelightRule_2: (x + y) - (x & y) => x | y
                rewrite((x + y) - (x & y)).to(x | y),
                # Or_HackersDelightRule_2_variant_1: (x - y) - (x & -y) => x | -y
                rewrite((x - y) - (x & -y)).to(x | (-y)),
                # Or_FactorRule_1: (x & y) | (x ^ y) => x | y
                rewrite((x & y) | (x ^ y)).to(x | y),
                # Or_Rule_2: (x ^ y) | y => x | y
                rewrite((x ^ y) | y).to(x | y),
                # Or_Rule_4: (x & y) ^ (x ^ y) => x | y
                rewrite((x & y) ^ (x ^ y)).to(x | y),
                # OrBnot_FactorRule_1: ~x ^ (x & y) => ~x | y
                rewrite((~x) ^ (x & y)).to((~x) | y),
                # OrBnot_FactorRule_2: x ^ (~x & y) => x | y
                rewrite(x ^ ((~x) & y)).to(x | y),
            )

            # ================================================================
            # AND MBA RULES (Hacker's Delight)
            # ================================================================
            self.egraph.register(
                # And_HackersDelightRule_1: (~x | y) - ~x => x & y
                rewrite(((~x) | y) - (~x)).to(x & y),
                # And_HackersDelightRule_3: (x + y) - (x | y) => x & y
                rewrite((x + y) - (x | y)).to(x & y),
                # And_HackersDelightRule_4: (x | y) - (x ^ y) => x & y
                rewrite((x | y) - (x ^ y)).to(x & y),
                # And_OllvmRule_1: (x | y) & ~(x ^ y) => x & y
                rewrite((x | y) & (~(x ^ y))).to(x & y),
                # And_FactorRule_1: (x | y) ^ (x ^ y) => x & y
                rewrite((x | y) ^ (x ^ y)).to(x & y),
                # And_FactorRule_2: x & ~(x ^ y) => x & y
                rewrite(x & (~(x ^ y))).to(x & y),
            )

            # ================================================================
            # AND-NOT RULES
            # ================================================================
            self.egraph.register(
                # AndBnot_HackersDelightRule_1: (x | y) - y => x & ~y
                rewrite((x | y) - y).to(x & (~y)),
                # AndBnot_HackersDelightRule_2: x - (x & y) => x & ~y
                rewrite(x - (x & y)).to(x & (~y)),
                # AndBnot_FactorRule_1: x ^ (x & y) => x & ~y
                rewrite(x ^ (x & y)).to(x & (~y)),
                # AndBnot_FactorRule_2: x & (x ^ y) => x & ~y
                rewrite(x & (x ^ y)).to(x & (~y)),
                # AndBnot_FactorRule_3: (x | y) ^ y => x & ~y
                rewrite((x | y) ^ y).to(x & (~y)),
            )

            # ================================================================
            # ADD MBA RULES (Hacker's Delight)
            # ================================================================
            self.egraph.register(
                # Add_HackersDelightRule_1: x - (~y + 1) => x + y
                rewrite(x - ((~y) + one)).to(x + y),
                # Add_HackersDelightRule_2: (x ^ y) + 2*(x & y) => x + y
                rewrite((x ^ y) + two * (x & y)).to(x + y),
                # Add_HackersDelightRule_3: (x | y) + (x & y) => x + y
                rewrite((x | y) + (x & y)).to(x + y),
                # Add_HackersDelightRule_4: 2*(x | y) - (x ^ y) => x + y
                rewrite(two * (x | y) - (x ^ y)).to(x + y),
            )

            # ================================================================
            # SUB MBA RULES (Hacker's Delight)
            # ================================================================
            self.egraph.register(
                # Sub_HackersDelightRule_1: x + (~y + 1) => x - y
                rewrite(x + ((~y) + one)).to(x - y),
                # Sub_HackersDelightRule_2: (x ^ y) - 2*(~x & y) => x - y
                rewrite((x ^ y) - two * ((~x) & y)).to(x - y),
                # Sub_HackersDelightRule_3: (x & ~y) - (~x & y) => x - y
                rewrite((x & (~y)) - ((~x) & y)).to(x - y),
                # Sub_HackersDelightRule_4: 2*(x & ~y) - (x ^ y) => x - y
                rewrite(two * (x & (~y)) - (x ^ y)).to(x - y),
            )

            # ================================================================
            # BNOT/NOT MBA RULES
            # ================================================================
            self.egraph.register(
                # Bnot_HackersDelightRule_1: -x - 1 => ~x
                rewrite((-x) - one).to(~x),
                # Bnot_MbaRule_1: (x - 1) - 2*x => ~x
                rewrite((x - one) - (two * x)).to(~x),
                # Bnot_FactorRule_1: ~(x ^ y) ^ y => ~x
                rewrite((~(x ^ y)) ^ y).to(~x),
                # Bnot_FactorRule_4: ~x ^ ~y => x ^ y
                rewrite((~x) ^ (~y)).to(x ^ y),
            )

            # ================================================================
            # DE MORGAN'S LAWS
            # ================================================================
            self.egraph.register(
                # BnotAnd_FactorRule_3: ~x | ~y => ~(x & y)
                rewrite((~x) | (~y)).to(~(x & y)),
                # BnotOr_FactorRule_1: ~x & ~y => ~(x | y)
                rewrite((~x) & (~y)).to(~(x | y)),
            )

            # ================================================================
            # XOR-NOT EQUIVALENCES
            # ================================================================
            # Mathematical identity: x ^ ~y == ~(x ^ y)
            # NOTE: Only one direction to avoid infinite loop with bidirectional rules
            self.egraph.register(
                rewrite(x ^ (~y)).to(~(x ^ y)),
            )

            # ================================================================
            # XNOR PATTERNS
            # ================================================================
            self.egraph.register(
                # Bnot_XorRule_1: (x & y) | ~(x | y) => ~(x ^ y)
                rewrite((x & y) | (~(x | y))).to(~(x ^ y)),
                # BnotAnd_FactorRule_1: (x ^ y) | ~(x | y) => ~(x & y)
                rewrite((x ^ y) | (~(x | y))).to(~(x & y)),
            )

            # ================================================================
            # NEGATION MBA RULES
            # ================================================================
            self.egraph.register(
                # Neg_HackersDelightRule_1: ~x + 1 => -x
                rewrite((~x) + one).to(-x),
                # Neg_HackersDelightRule_2: ~(x - 1) => -x
                rewrite(~(x - one)).to(-x),
                # NegSub_HackersDelightRule_1: (x ^ y) - 2*(x | y) => -(x + y)
                rewrite((x ^ y) - two * (x | y)).to(-(x + y)),
                # NegOr_HackersDelightRule_1: (x & y) - (x + y) => -(x | y)
                rewrite((x & y) - (x + y)).to(-(x | y)),
                # NegXor_HackersDelightRule_1: (x & y) - (x | y) => -(x ^ y)
                rewrite((x & y) - (x | y)).to(-(x ^ y)),
                # NegXor_HackersDelightRule_2: (x + y) - 2*(x | y) => -(x ^ y)
                rewrite((x + y) - two * (x | y)).to(-(x ^ y)),
            )

            # ================================================================
            # ALWAYS-ZERO PATTERNS
            # ================================================================
            self.egraph.register(
                # Pred0Rule3: x & ~x => 0
                rewrite(x & (~x)).to(zero),
                # Pred0Rule5: x & ~(x | y) => 0
                rewrite(x & (~(x | y))).to(zero),
                # Pred0Rule6: (x & y) & ~(x | y) => 0
                rewrite((x & y) & (~(x | y))).to(zero),
                # Pred0Rule7: (x & y) & (x ^ y) => 0
                rewrite((x & y) & (x ^ y)).to(zero),
            )

            # ================================================================
            # ABSORPTION LAWS
            # ================================================================
            self.egraph.register(
                # GetIdentRule3: x & (x | y) => x (Absorption law)
                rewrite(x & (x | y)).to(x),
            )

            # ================================================================
            # DISTRIBUTIVE LAWS
            # ================================================================
            self.egraph.register(
                # AndOr_FactorRule_1: (x & z) | (y & z) => (x | y) & z
                rewrite((x & z) | (y & z)).to((x | y) & z),
                # AndXor_FactorRule_1: (x & z) ^ (y & z) => (x ^ y) & z
                rewrite((x & z) ^ (y & z)).to((x ^ y) & z),
            )

            # ================================================================
            # SUB-ONE MBA RULES
            # ================================================================
            self.egraph.register(
                # Sub1_FactorRule_2: 2*x + ~x => x - 1
                rewrite(two * x + (~x)).to(x - one),
                # Sub1Or_MbaRule_1: (x + y) + ~(x & y) => (x | y) - 1
                rewrite((x + y) + (~(x & y))).to((x | y) - one),
            )

            # ================================================================
            # OLLVM DEOBFUSCATION PATTERNS
            # ================================================================
            self.egraph.register(
                # Add_OllvmRule_1: ~(x ^ y) + 2*(y | x) => (x + y) - 1
                rewrite((~(x ^ y)) + two * (y | x)).to((x + y) - one),
            )

            # ================================================================
            # HODUR DEOBFUSCATION PATTERNS
            # ================================================================
            self.egraph.register(
                # Xor_Hodur_1: ~(x ^ (y ^ z)) => x ^ (y ^ ~z)
                rewrite(~(x ^ (y ^ z))).to(x ^ (y ^ (~z))),
            )

        def add_expression(self, name: str, expr: BitExpr) -> BitExpr:
            """Add an expression to the e-graph."""
            self.egraph.register(expr)
            return expr

        def saturate(self):
            """Run equality saturation to discover all equivalences.

            Uses iterative saturation with early termination to prevent
            e-graph explosion from bidirectional or cyclic rules.
            """
            for i in range(self.max_iterations):
                try:
                    report = self.egraph.run(1)
                    # egglog returns a report with stop_reason
                    if hasattr(report, 'stop_reason') and str(report.stop_reason) == "Saturated":
                        break
                except Exception as e:
                    logger.warning(f"E-graph saturation stopped at iteration {i}: {e}")
                    break

        def check_equivalent(self, expr1: BitExpr, expr2: BitExpr) -> bool:
            """Check if two expressions are equivalent after saturation."""
            try:
                self.egraph.check(eq(expr1).to(expr2))
                return True
            except Exception:
                return False

        def var(self, name: str) -> BitExpr:
            """Create a variable expression."""
            return BitExpr.var(name)

        def const(self, value: int) -> BitExpr:
            """Create a constant expression."""
            return BitExpr(value)

    # IDA opcode to BitExpr operation mapping
    # Only populated when ida_hexrays is available (inside IDA)
    if ida_hexrays is not None:
        _OPCODE_TO_BITEXPR_BINARY = {
            ida_hexrays.m_add: lambda l, r: l + r,
            ida_hexrays.m_sub: lambda l, r: l - r,
            ida_hexrays.m_mul: lambda l, r: l * r,
            ida_hexrays.m_and: lambda l, r: l & r,
            ida_hexrays.m_or: lambda l, r: l | r,
            ida_hexrays.m_xor: lambda l, r: l ^ r,
        }

        _OPCODE_TO_BITEXPR_UNARY = {
            ida_hexrays.m_neg: lambda x: -x,
            ida_hexrays.m_bnot: lambda x: ~x,
        }

        # BitExpr operation to IDA opcode mapping (for extraction)
        # Note: These are string representations from egglog
        _BITEXPR_OP_TO_OPCODE = {
            "__add__": ida_hexrays.m_add,
            "__sub__": ida_hexrays.m_sub,
            "__mul__": ida_hexrays.m_mul,
            "__and__": ida_hexrays.m_and,
            "__or__": ida_hexrays.m_or,
            "__xor__": ida_hexrays.m_xor,
            "__neg__": ida_hexrays.m_neg,
            "__invert__": ida_hexrays.m_bnot,
        }
    else:
        # Empty mappings when not in IDA
        _OPCODE_TO_BITEXPR_BINARY = {}
        _OPCODE_TO_BITEXPR_UNARY = {}
        _BITEXPR_OP_TO_OPCODE = {}

    class AstToBitExprConverter:
        """Converts IDA AstNode to egglog BitExpr."""

        def __init__(self):
            self._var_counter = 0
            self._leaf_to_var: dict[int, BitExpr] = {}
            self._var_to_leaf: dict[str, typing.Any] = {}  # AstLeaf

        def convert(self, ast_node) -> BitExpr | None:
            """Convert an AstNode/AstLeaf to BitExpr.

            Args:
                ast_node: The AstNode or AstLeaf to convert.

            Returns:
                BitExpr representation, or None if conversion fails.
            """
            import importlib

            _ast_mod = importlib.import_module("d810.expr.ast")
            AstConstantProtocol = _ast_mod.AstConstantProtocol
            AstLeafProtocol = _ast_mod.AstLeafProtocol
            AstNodeProtocol = _ast_mod.AstNodeProtocol

            if ast_node is None:
                return None

            # Handle leaf nodes (variables) - use Protocols for hot-reload safety
            if isinstance(ast_node, (AstLeafProtocol, AstConstantProtocol)) or ast_node.is_leaf():
                return self._convert_leaf(ast_node)

            # Handle AstNode - use Protocol for hot-reload safety
            if isinstance(ast_node, AstNodeProtocol) or ast_node.is_node():
                return self._convert_node(ast_node)

            return None

        def _convert_leaf(self, leaf) -> BitExpr:
            """Convert a leaf node to a BitExpr variable or constant.

            If the leaf is a constant (AstConstant with a known value), it is
            converted to a BitExpr literal. This is crucial for MBA rules that
            use specific constants like 2 (e.g., (a+b) - 2*(a&b) => a^b).

            Non-constant leaves (registers, variables) are converted to BitExpr
            variables for symbolic manipulation.
            """
            # Check if leaf is a constant with a known value
            # Use duck typing: check for is_constant() method and value attribute
            is_constant = getattr(leaf, "is_constant", lambda: False)()
            if is_constant:
                value = getattr(leaf, "value", None)
                if value is not None:
                    # Convert to BitExpr constant literal
                    return BitExpr(value)

            # Use ast_index as unique identifier if available
            leaf_id = getattr(leaf, "ast_index", id(leaf))

            if leaf_id in self._leaf_to_var:
                return self._leaf_to_var[leaf_id]

            # Create new variable
            var_name = f"v{self._var_counter}"
            self._var_counter += 1
            var = BitExpr.var(var_name)

            self._leaf_to_var[leaf_id] = var
            self._var_to_leaf[var_name] = leaf

            return var

        def _convert_node(self, node) -> BitExpr | None:
            """Convert an AstNode to BitExpr."""
            opcode = node.opcode

            # Binary operations
            if opcode in _OPCODE_TO_BITEXPR_BINARY:
                left = self.convert(node.left)
                right = self.convert(node.right)
                if left is None or right is None:
                    return None
                return _OPCODE_TO_BITEXPR_BINARY[opcode](left, right)

            # Unary operations
            if opcode in _OPCODE_TO_BITEXPR_UNARY:
                operand = self.convert(node.left)
                if operand is None:
                    return None
                return _OPCODE_TO_BITEXPR_UNARY[opcode](operand)

            # Unsupported opcode - treat as leaf
            return self._convert_leaf(node)

        def get_leaf_mapping(self) -> dict[str, typing.Any]:
            """Get the mapping from variable names to original leaves."""
            return self._var_to_leaf.copy()

    class EGraphOptimizer:
        """IDA microcode optimizer using e-graphs and equality saturation.

        This optimizer replaces the traditional pattern matching approach
        with e-graph based equivalence checking. Instead of generating
        all commutative variations, it uses rewrite rules to discover
        equivalences automatically.
        """

        def __init__(self, max_iterations: int = 10):
            """Initialize the optimizer.

            Args:
                max_iterations: Maximum saturation iterations per expression.
            """
            self.max_iterations = max_iterations
            self.name = "EGraphOptimizer"
            self._stats = {"conversions": 0, "simplifications": 0, "failures": 0}

        def try_simplify(self, ast_node) -> typing.Any | None:
            """Try to simplify an AST node using e-graph equality saturation.

            Args:
                ast_node: The AstNode to simplify.

            Returns:
                Simplified AstNode if a simplification was found, None otherwise.
            """
            import importlib

            AstNode = importlib.import_module("d810.expr.ast").AstNode

            # Convert to BitExpr
            converter = AstToBitExprConverter()
            bit_expr = converter.convert(ast_node)
            if bit_expr is None:
                self._stats["failures"] += 1
                return None

            self._stats["conversions"] += 1

            # Create e-graph and add expression
            egraph = MBAEGraph(max_iterations=self.max_iterations)
            egraph.add_expression("input", bit_expr)

            # Get leaf mapping for reconstruction
            leaf_mapping = converter.get_leaf_mapping()

            # Create all possible simplified targets and check equivalence
            simplified = self._find_simplification(egraph, bit_expr, leaf_mapping)

            if simplified is not None:
                self._stats["simplifications"] += 1

            return simplified

        def _find_simplification(
            self,
            egraph: MBAEGraph,
            original: BitExpr,
            leaf_mapping: dict[str, typing.Any],
        ) -> typing.Any | None:
            """Find a simpler equivalent expression.

            This method creates candidate simplified expressions and checks
            if they're equivalent to the original using equality saturation.
            """
            import importlib

            AstNode = importlib.import_module("d810.expr.ast").AstNode

            # If we have exactly 2 variables, try standard MBA simplifications
            if len(leaf_mapping) != 2:
                return None

            var_names = sorted(leaf_mapping.keys())
            x_name, y_name = var_names[0], var_names[1]
            x_leaf, y_leaf = leaf_mapping[x_name], leaf_mapping[y_name]

            x = BitExpr.var(x_name)
            y = BitExpr.var(y_name)

            # Candidate simplifications (from complex to simple)
            # Note: ida_hexrays is only used when actually running inside IDA
            if ida_hexrays is None:
                return None

            candidates = [
                (x | y, ida_hexrays.m_or, "OR"),
                (x & y, ida_hexrays.m_and, "AND"),
                (x ^ y, ida_hexrays.m_xor, "XOR"),
                (x, None, "X"),
                (y, None, "Y"),
            ]

            # Add candidates to e-graph
            for expr, _, _ in candidates:
                egraph.add_expression("candidate", expr)

            # Run saturation
            egraph.saturate()

            # Check each candidate for equivalence
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

        def get_stats(self) -> dict:
            """Get optimization statistics."""
            return self._stats.copy()

    # =========================================================================
    # Pattern Generation for VerifiableRule
    # =========================================================================
    # These functions use egglog at STARTUP TIME to generate all equivalent
    # pattern variants from a single base pattern. This eliminates the need
    # for manually-defined *_Commuted rule variants.

    class PatternExpr(Expr):
        """Expression type for pattern generation (commutativity checking)."""

        @classmethod
        def var(cls, name: StringLike) -> "PatternExpr":
            """Create a variable."""
            ...

        def __add__(self, other: "PatternExpr") -> "PatternExpr": ...
        def __sub__(self, other: "PatternExpr") -> "PatternExpr": ...
        def __and__(self, other: "PatternExpr") -> "PatternExpr": ...
        def __or__(self, other: "PatternExpr") -> "PatternExpr": ...
        def __xor__(self, other: "PatternExpr") -> "PatternExpr": ...
        def __mul__(self, other: "PatternExpr") -> "PatternExpr": ...
        def __neg__(self) -> "PatternExpr": ...
        def __invert__(self) -> "PatternExpr": ...

    def _create_pattern_egraph() -> EGraph:
        """Create an e-graph with commutativity rules for pattern generation."""
        egraph = EGraph()

        # Create rule variables
        a, b = vars_("a b", PatternExpr)

        # Register commutativity rules for all commutative operators
        egraph.register(
            rewrite(a + b).to(b + a),
            rewrite(a & b).to(b & a),
            rewrite(a | b).to(b | a),
            rewrite(a ^ b).to(b ^ a),
            rewrite(a * b).to(b * a),
        )

        # XOR-NOT equivalence (handles inverse rules like BnotXor/CstSimpl)
        # Mathematical identity: a ^ ~b == ~(a ^ b)
        # NOTE: Only one direction to avoid infinite loop with bidirectional rules
        egraph.register(
            rewrite(a ^ (~b)).to(~(a ^ b)),
        )

        return egraph

    def verify_pattern_equivalence(
        expr1: "PatternExpr",
        expr2: "PatternExpr",
        max_iterations: int = 10,
    ) -> bool:
        """Check if two pattern expressions are equivalent under commutativity.

        Args:
            expr1: First pattern expression.
            expr2: Second pattern expression.
            max_iterations: Maximum saturation iterations.

        Returns:
            True if the expressions are equivalent, False otherwise.
        """
        egraph = _create_pattern_egraph()
        egraph.register(expr1)
        egraph.register(expr2)
        egraph.run(max_iterations)

        try:
            egraph.check(eq(expr1).to(expr2))
            return True
        except Exception:
            return False

    def generate_equivalent_patterns(
        base_pattern: "PatternExpr",
        candidates: list["PatternExpr"],
        max_iterations: int = 10,
    ) -> list["PatternExpr"]:
        """Use egglog to find which candidate patterns are equivalent to base.

        This function is used at STARTUP TIME to generate all equivalent
        pattern variants from a single base pattern. The overhead is acceptable
        because it only runs once per rule, not per instruction.

        Args:
            base_pattern: The base pattern expression.
            candidates: List of candidate patterns to check.
            max_iterations: Maximum saturation iterations.

        Returns:
            List of patterns equivalent to base_pattern (including base itself).
        """
        egraph = _create_pattern_egraph()

        # Add base pattern
        egraph.register(base_pattern)

        # Add all candidates
        for candidate in candidates:
            egraph.register(candidate)

        # Run saturation to discover equivalences
        egraph.run(max_iterations)

        # Check which candidates are equivalent to base
        equivalent = [base_pattern]
        for candidate in candidates:
            try:
                egraph.check(eq(base_pattern).to(candidate))
                if candidate not in equivalent:
                    equivalent.append(candidate)
            except Exception:
                pass  # Not equivalent

        return equivalent


# Example usage and testing
if __name__ == "__main__":
    if not EGGLOG_AVAILABLE:
        print("egglog not installed. Run: pip install egglog cloudpickle")
        exit(1)

    # print("Testing egglog-based MBA pattern matching...")
    # print("=" * 60)

    # # Create e-graph
    # egraph = MBAEGraph()

    # # Create variables
    # x = egraph.var("x")
    # y = egraph.var("y")

    # # Test cases
    # test_cases = [
    #     # (obfuscated_expr, expected_simplified, description)
    #     ((x & y) + (x ^ y), x | y, "Or_MbaRule_1: (x & y) + (x ^ y) => x | y"),
    #     (
    #         (x ^ y) + (x & y),
    #         x | y,
    #         "Or_MbaRule_1 (commuted): (x ^ y) + (x & y) => x | y",
    #     ),
    #     (
    #         (x + y) - (x & y),
    #         x | y,
    #         "Or_HackersDelightRule_2: (x + y) - (x & y) => x | y",
    #     ),
    #     ((x & y) | (x ^ y), x | y, "Or_FactorRule_1: (x & y) | (x ^ y) => x | y"),
    #     ((x | y) - (x ^ y), x & y, "And_MbaRule_1: (x | y) - (x ^ y) => x & y"),
    #     ((x | y) - (x & y), x ^ y, "Xor_MbaRule_1: (x | y) - (x & y) => x ^ y"),
    #     ((~x) ^ (x & y), (~x) | y, "OrBnot_FactorRule_1: ~x ^ (x & y) => ~x | y"),
    #     (x ^ ((~x) & y), x | y, "OrBnot_FactorRule_2: x ^ (~x & y) => x | y"),
    #     ((x ^ y) ^ y, x, "Xor_Rule_1: (x ^ y) ^ y => x"),
    # ]

    # # Add all expressions
    # for i, (obf, simp, desc) in enumerate(test_cases):
    #     egraph.add_expression(f"obf_{i}", obf)
    #     egraph.add_expression(f"simp_{i}", simp)

    # # Run saturation once
    # egraph.saturate()

    # # Check all equivalences
    # passed = 0
    # for obf, simp, desc in test_cases:
    #     is_equiv = egraph.check_equivalent(obf, simp)
    #     status = "PASS" if is_equiv else "FAIL"
    #     print(f"[{status}] {desc}")
    #     if is_equiv:
    #         passed += 1

    # print("=" * 60)
    # print(f"Results: {passed}/{len(test_cases)} tests passed")

    # if passed == len(test_cases):
    #     print("\nE-graph successfully proves all MBA equivalences!")
    #     print("This eliminates the need for explicit commuted rule variants.")
