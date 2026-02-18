"""Concrete interpreter for microcode ASTs.

Extracted from ``AstNode.evaluate()`` in Phase 2 of the evaluator package
refactor (see ``docs/plans/2026-02-18-evaluator-package-refactor.md``).

:class:`ConcreteEvaluator` is the canonical tree-walk interpreter that
computes a single concrete integer value for a microcode AST whose every
leaf is bound.  It is stateless: all state comes from the *node* and *env*
parameters passed to :meth:`evaluate`.

A module-level singleton ``_default_evaluator`` is provided so callers do
not allocate a new instance per call.  When the Cython fast path is
available it is swapped in at import time (Phase 5).

Usage::

    from d810.evaluator.concrete import evaluate_concrete

    result = evaluate_concrete(ast_node, {leaf_idx: value, ...})
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


class ConcreteEvaluator:
    """Concrete microcode AST interpreter.

    Replaces the ``evaluate()`` method on ``AstNode`` / ``AstLeaf``.
    Can be swapped for the Cython fast path
    (:class:`d810.speedups.evaluator.c_concrete.CythonConcreteEvaluator`)
    at runtime by reassigning :data:`_default_evaluator`.

    The evaluator is stateless; the same instance is safe to call from
    multiple call sites without any locking.

    Examples:
        >>> ev = ConcreteEvaluator()
        >>> isinstance(ev, ConcreteEvaluator)
        True
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, node: object, env: dict[int, int]) -> int:
        """Evaluate *node* given concrete leaf bindings in *env*.

        This is the primary dispatch entry point.  It calls either
        :meth:`_eval_node` or :meth:`_eval_leaf` depending on whether
        *node* is an interior node or a leaf.

        Args:
            node: Root of the AST to evaluate.  In practice an
                ``AstBase`` instance, but typed as ``object`` here to
                avoid a mandatory IDA import at module level.
            env: Mapping from ``ast_index`` to concrete integer value for
                each variable leaf.  Constant leaves do not need an
                entry.

        Returns:
            Concrete integer result, masked to ``node.dest_size`` bits.

        Raises:
            AstEvaluationException: If the AST contains an unsupported
                opcode or a required binding is missing.
        """
        if node.is_leaf():  # type: ignore[union-attr]
            return self._eval_leaf(node, env)
        return self._eval_node(node, env)

    def evaluate_with_leaf_info(
        self,
        node: object,
        leafs_info: list,
        leafs_value: list[int],
    ) -> int:
        """Evaluate *node* using per-leaf info objects and a value list.

        Convenience wrapper used by ``Z3ConstantOptimization`` and the
        ``AstNode.evaluate_with_leaf_info`` shim.

        Args:
            node: Root of the AST to evaluate.
            leafs_info: List of ``AstInfo``-like objects whose ``.ast``
                attribute exposes an ``ast_index`` integer.
            leafs_value: Parallel list of concrete integer values.

        Returns:
            Concrete integer result.
        """
        env: dict[int, int] = {
            li.ast.ast_index: lv
            for li, lv in zip(leafs_info, leafs_value)
            if li.ast.ast_index is not None
        }
        return self.evaluate(node, env)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _eval_leaf(self, node: object, env: dict[int, int]) -> int:
        """Evaluate a leaf node (``AstLeaf`` / ``AstConstant``).

        Args:
            node: An ``AstLeaf`` or ``AstConstant`` instance.
            env: Concrete binding map.

        Returns:
            The leaf's integer value: either the constant value stored in
            the mop, or the value looked up from *env* by ``ast_index``.
        """
        # AstConstant.evaluate() path — mop or expected_value
        if node.is_constant():  # type: ignore[union-attr]
            mop = node.mop  # type: ignore[union-attr]
            if mop is not None:
                # MopSnapshot exposes .value directly
                if hasattr(mop, "is_constant"):
                    return mop.value  # MopSnapshot
                # Raw mop_t — import ida_hexrays lazily
                import ida_hexrays
                if mop.t == ida_hexrays.mop_n:
                    return mop.nnn.value
            # Fall back to expected_value (AstConstant computed-constant path)
            return node.expected_value  # type: ignore[union-attr]

        # AstLeaf.evaluate() path — look up in env
        assert node.ast_index is not None  # type: ignore[union-attr]
        return env.get(node.ast_index)  # type: ignore[union-attr, return-value]

    def _eval_node(self, node: object, env: dict[int, int]) -> int:
        """Evaluate an interior ``AstNode``.

        Implements the full opcode dispatch chain extracted verbatim from
        ``AstNode.evaluate()``.  All ``ida_hexrays`` opcode constants are
        imported lazily so this module can be imported without IDA present
        (allowing pure-Python unit tests).

        Args:
            node: An ``AstNode`` instance.
            env: Concrete binding map.

        Returns:
            Concrete integer result masked to ``node.dest_size`` bits.

        Raises:
            AstEvaluationException: For unsupported opcodes.
            ValueError: If required operands are missing.
        """
        # Lazy IDA import — keeps module importable without IDA
        import ida_hexrays

        from d810.core.bits import (
            AND_TABLE,
            get_add_cf,
            get_add_of,
            get_parity_flag,
            get_sub_of,
            signed_to_unsigned,
            unsigned_to_signed,
        )
        from d810.errors import AstEvaluationException
        from d810.evaluator.helpers import get_registry

        # ------------------------------------------------------------------
        # Short-circuit: if this node's index is directly in env, return it.
        # (Mirrors the early-exit in the original AstNode.evaluate().)
        # ------------------------------------------------------------------
        if node.ast_index in env:  # type: ignore[union-attr, operator]
            return env[node.ast_index]  # type: ignore[union-attr]

        if node.dest_size is None:  # type: ignore[union-attr]
            raise ValueError("dest_size is None")

        res_mask = AND_TABLE[node.dest_size]  # type: ignore[union-attr]

        if node.left is None:  # type: ignore[union-attr]
            raise ValueError(f"left is None for opcode: {node.opcode}")  # type: ignore[union-attr]

        binary_opcodes = {
            ida_hexrays.m_add,
            ida_hexrays.m_sub,
            ida_hexrays.m_mul,
            ida_hexrays.m_udiv,
            ida_hexrays.m_sdiv,
            ida_hexrays.m_umod,
            ida_hexrays.m_smod,
            ida_hexrays.m_or,
            ida_hexrays.m_and,
            ida_hexrays.m_xor,
            ida_hexrays.m_shl,
            ida_hexrays.m_shr,
            ida_hexrays.m_sar,
            ida_hexrays.m_cfadd,
            ida_hexrays.m_ofadd,
            ida_hexrays.m_seto,
            ida_hexrays.m_setnz,
            ida_hexrays.m_setz,
            ida_hexrays.m_setae,
            ida_hexrays.m_setb,
            ida_hexrays.m_seta,
            ida_hexrays.m_setbe,
            ida_hexrays.m_setg,
            ida_hexrays.m_setge,
            ida_hexrays.m_setl,
            ida_hexrays.m_setle,
            ida_hexrays.m_setp,
        }

        if node.opcode in binary_opcodes and node.right is None:  # type: ignore[union-attr]
            raise ValueError(
                "right is None for binary opcode: {0}".format(node.opcode)  # type: ignore[union-attr]
            )

        # Helper to recursively evaluate a child node
        def _ev(child: object) -> int:
            return self.evaluate(child, env)

        opcode = node.opcode  # type: ignore[union-attr]
        left = node.left  # type: ignore[union-attr]
        right = node.right  # type: ignore[union-attr]

        match opcode:
            case ida_hexrays.m_mov:
                return _ev(left) & res_mask
            case ida_hexrays.m_neg:
                return (-_ev(left)) & res_mask
            case ida_hexrays.m_lnot:
                return _ev(left) != 0
            case ida_hexrays.m_bnot:
                return (_ev(left) ^ res_mask) & res_mask
            case ida_hexrays.m_xds:
                left_value_signed = unsigned_to_signed(
                    _ev(left), left.dest_size
                )
                return (
                    signed_to_unsigned(left_value_signed, node.dest_size)  # type: ignore[union-attr]
                    & res_mask
                )
            case ida_hexrays.m_xdu:
                return _ev(left) & res_mask
            case ida_hexrays.m_low:
                return _ev(left) & res_mask
            case ida_hexrays.m_high:
                if left.dest_size is None:
                    raise ValueError("left.dest_size is None for m_high")
                shift_bits = (
                    node.dest_size * 8  # type: ignore[union-attr]
                    if node.dest_size is not None  # type: ignore[union-attr]
                    else 0
                )
                return (_ev(left) >> shift_bits) & res_mask
            case ida_hexrays.m_add if right is not None:
                return (_ev(left) + _ev(right)) & res_mask
            case ida_hexrays.m_sub if right is not None:
                return (_ev(left) - _ev(right)) & res_mask
            case ida_hexrays.m_mul if right is not None:
                return (_ev(left) * _ev(right)) & res_mask
            case ida_hexrays.m_udiv if right is not None:
                return (_ev(left) // _ev(right)) & res_mask
            case ida_hexrays.m_sdiv if right is not None:
                return (_ev(left) // _ev(right)) & res_mask
            case ida_hexrays.m_umod if right is not None:
                return (_ev(left) % _ev(right)) & res_mask
            case ida_hexrays.m_smod if right is not None:
                return (_ev(left) % _ev(right)) & res_mask
            case ida_hexrays.m_or if right is not None:
                return (_ev(left) | _ev(right)) & res_mask
            case ida_hexrays.m_and if right is not None:
                return (_ev(left) & _ev(right)) & res_mask
            case ida_hexrays.m_xor if right is not None:
                return (_ev(left) ^ _ev(right)) & res_mask
            case ida_hexrays.m_shl if right is not None:
                return (_ev(left) << _ev(right)) & res_mask
            case ida_hexrays.m_shr if right is not None:
                return (_ev(left) >> _ev(right)) & res_mask
            case ida_hexrays.m_sar if right is not None:
                left_value_signed = unsigned_to_signed(
                    _ev(left), left.dest_size
                )
                res_signed = left_value_signed >> _ev(right)
                return (
                    signed_to_unsigned(res_signed, node.dest_size)  # type: ignore[union-attr]
                    & res_mask
                )
            case ida_hexrays.m_cfadd if right is not None:
                tmp = get_add_cf(
                    _ev(left),
                    _ev(right),
                    left.dest_size,
                )
                return tmp & res_mask
            case ida_hexrays.m_ofadd if right is not None:
                tmp = get_add_of(
                    _ev(left),
                    _ev(right),
                    left.dest_size,
                )
                return tmp & res_mask
            case ida_hexrays.m_sets:
                left_value_signed = unsigned_to_signed(
                    _ev(left), left.dest_size
                )
                res = 1 if left_value_signed < 0 else 0
                return res & res_mask
            case ida_hexrays.m_seto if right is not None:
                left_value_signed = unsigned_to_signed(
                    _ev(left), left.dest_size
                )
                right_value_signed = unsigned_to_signed(
                    _ev(right), right.dest_size
                )
                sub_overflow = get_sub_of(
                    left_value_signed,
                    right_value_signed,
                    left.dest_size,
                )
                return sub_overflow & res_mask
            case ida_hexrays.m_setnz if right is not None:
                res = 1 if _ev(left) != _ev(right) else 0
                return res & res_mask
            case ida_hexrays.m_setz if right is not None:
                res = 1 if _ev(left) == _ev(right) else 0
                return res & res_mask
            case ida_hexrays.m_setae if right is not None:
                res = 1 if _ev(left) >= _ev(right) else 0
                return res & res_mask
            case ida_hexrays.m_setb if right is not None:
                res = 1 if _ev(left) < _ev(right) else 0
                return res & res_mask
            case ida_hexrays.m_seta if right is not None:
                res = 1 if _ev(left) > _ev(right) else 0
                return res & res_mask
            case ida_hexrays.m_setbe if right is not None:
                res = 1 if _ev(left) <= _ev(right) else 0
                return res & res_mask
            case ida_hexrays.m_setg if right is not None:
                left_value_signed = unsigned_to_signed(
                    _ev(left), left.dest_size
                )
                right_value_signed = unsigned_to_signed(
                    _ev(right), right.dest_size
                )
                res = 1 if left_value_signed > right_value_signed else 0
                return res & res_mask
            case ida_hexrays.m_setge if right is not None:
                left_value_signed = unsigned_to_signed(
                    _ev(left), left.dest_size
                )
                right_value_signed = unsigned_to_signed(
                    _ev(right), right.dest_size
                )
                res = 1 if left_value_signed >= right_value_signed else 0
                return res & res_mask
            case ida_hexrays.m_setl if right is not None:
                left_value_signed = unsigned_to_signed(
                    _ev(left), left.dest_size
                )
                right_value_signed = unsigned_to_signed(
                    _ev(right), right.dest_size
                )
                res = 1 if left_value_signed < right_value_signed else 0
                return res & res_mask
            case ida_hexrays.m_setle if right is not None:
                left_value_signed = unsigned_to_signed(
                    _ev(left), left.dest_size
                )
                right_value_signed = unsigned_to_signed(
                    _ev(right), right.dest_size
                )
                res = 1 if left_value_signed <= right_value_signed else 0
                return res & res_mask
            case ida_hexrays.m_setp if right is not None:
                res = get_parity_flag(
                    _ev(left),
                    _ev(right),
                    left.dest_size,
                )
                return res & res_mask
            case ida_hexrays.m_call:
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(
                        "evaluate m_call: ast_index=%s, dest_size=%s, func_name=%s",
                        node.ast_index,  # type: ignore[union-attr]
                        node.dest_size,  # type: ignore[union-attr]
                        getattr(node, "func_name", ""),
                    )
                # Attempt to evaluate rotate helper calls (__ROL*/__ROR*).
                # func_name is populated by mop_to_ast_internal when building
                # AST nodes for rotate helper calls.
                helper_name = (getattr(node, "func_name", "") or "").lstrip("!")
                if (
                    helper_name
                    and (
                        helper_name.startswith("__ROL")
                        or helper_name.startswith("__ROR")
                    )
                    and left is not None
                    and right is not None
                ):
                    helper_func = get_registry().lookup(helper_name)
                    if helper_func is not None:
                        val = _ev(left)
                        rot = _ev(right)
                        result = helper_func(val, rot)
                        return result & res_mask
                # Unknown runtime value — treat as 0 to let constant
                # evaluation proceed (matches original behaviour).
                return 0 & res_mask
            case _:
                raise AstEvaluationException(
                    "Can't evaluate opcode: {0}".format(opcode)
                )


# ---------------------------------------------------------------------------
# Module-level singleton — callers import and call evaluate_concrete()
# ---------------------------------------------------------------------------

_default_evaluator: ConcreteEvaluator = ConcreteEvaluator()

# Phase 5: swap in Cython fast path when available
try:
    from d810.speedups.evaluator.c_concrete import (  # type: ignore[import]
        CythonConcreteEvaluator,
    )
    _default_evaluator = CythonConcreteEvaluator()
except ImportError:
    pass


def evaluate_concrete(
    node: object,
    env: dict[int, int],
    *,
    evaluator: object | None = None,
) -> int:
    """Public entry point for concrete AST evaluation.

    Uses the Cython evaluator when available (Phase 5), otherwise falls
    back to the pure-Python :class:`ConcreteEvaluator`.

    Args:
        node: Root of the AST to evaluate (``AstBase`` instance).
        env: Mapping from ``ast_index`` to concrete integer value for
            each variable leaf.
        evaluator: Optional override.  If ``None``, :data:`_default_evaluator`
            is used.

    Returns:
        Concrete integer result masked to ``node.dest_size`` bits.
    """
    ev = evaluator if evaluator is not None else _default_evaluator
    return ev.evaluate(node, env)  # type: ignore[union-attr]


__all__ = [
    "ConcreteEvaluator",
    "evaluate_concrete",
    "_default_evaluator",
]
