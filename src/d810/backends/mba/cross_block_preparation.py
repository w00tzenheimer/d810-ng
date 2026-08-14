"""Read-only cross-block constant preparation for bounded MBA candidates.

This module is intentionally not a second constant-propagation optimizer.
It reuses the public forward constant lattice to specialize a *clone* of one
candidate AST.  The caller retains the original AST for the final native Z3
equivalence gate and never mutates the live MBA instruction during discovery.

Only stack operands are substituted here.  That is the conservative identity
already used by :class:`ForwardConstantPropagationRule`: stack storage remains
stable across Hex-Rays SSA versions while registers keep their SSA identity.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

from d810.core.typing import Any, Callable, Mapping
from d810.evaluator.hexrays_microcode.forward_dataflow import (
    ConstMap,
    build_constant_entry_state,
    constant_transfer_block,
    constant_transfer_single,
    run_forward_fixpoint_on_mba,
)
from d810.hexrays.ir.mop_snapshot import MopSnapshot
from d810.hexrays.ir.mop_utils import constant_propagation_var_name
from d810.ir.lattice import Const, LatticeMeet, TOP


@dataclass(frozen=True, slots=True)
class PreparedCrossBlockAst:
    """A disposable AST specialized by proven pre-instruction constants."""

    ast: Any
    substitutions: int
    environment: Mapping[str, object]
    known_constants: Mapping[tuple[object, ...], int]


def constant_environment_before_instruction(
    mba: object,
    block: object,
    instruction: object,
) -> Mapping[str, object] | None:
    """Return the converged constant environment immediately before *instruction*.

    The returned map is immutable.  The function fails closed when the target
    instruction cannot be found in the supplied block; in particular it never
    falls back to matching an EA, which is not a unique microcode identity.
    """

    def transfer(serial: int, in_state: ConstMap) -> ConstMap:
        return constant_transfer_block(mba.get_mblock(serial), in_state)

    try:
        result = run_forward_fixpoint_on_mba(
            mba,
            entry_state=build_constant_entry_state(mba),
            bottom={},
            meet=LatticeMeet(default_missing=TOP).meet,
            transfer=transfer,
            raise_on_nonconvergence=True,
        )
        environment: ConstMap = dict(result.in_states[int(block.serial)])
    except Exception:
        return None

    current = getattr(block, "head", None)
    while current:
        if _same_instruction(current, instruction):
            return MappingProxyType(environment)
        try:
            constant_transfer_single(mba, current, environment)
        except Exception:
            return None
        current = getattr(current, "next", None)
    return None


def rewrite_ast_with_constant_resolver(
    ast: Any,
    *,
    resolve_constant: Callable[[Any], tuple[int, int] | None],
) -> tuple[Any, int]:
    """Clone *ast* and replace leaves accepted by ``resolve_constant``.

    This generic clone-only primitive is kept separate from the live MBA
    lookup so it can be tested without a CFG.  A resolver returning ``None``
    leaves that exact cloned leaf untouched.
    """

    try:
        from d810.hexrays.expr import ast as runtime
        from d810.hexrays.expr.ast import get_constant_mop
    except ImportError:
        return ast, 0

    substitutions = 0

    def rewrite(node: Any) -> Any:
        nonlocal substitutions
        if isinstance(node, runtime.AstLeaf):
            resolved = resolve_constant(node)
            if resolved is None:
                return node.clone()
            value, size = resolved
            if size not in {1, 2, 4, 8}:
                return node.clone()
            replacement = runtime.AstConstant(hex(value), value, size)
            replacement.mop = get_constant_mop(value, size)
            replacement.dest_size = size
            replacement.ea = getattr(node, "ea", None)
            substitutions += 1
            return replacement
        if not isinstance(node, runtime.AstNode):
            return node.clone()
        clone = node.clone()
        if node.left is not None:
            clone.left = rewrite(node.left)
        if node.right is not None:
            clone.right = rewrite(node.right)
        if node.dst is not None:
            clone.dst = rewrite(node.dst)
        return clone

    return rewrite(ast), substitutions


def prepare_ast_with_cross_block_constants(
    mba: object,
    block: object,
    instruction: object,
    ast: Any,
) -> PreparedCrossBlockAst | None:
    """Specialize a candidate clone with exact FCP facts, or abstain.

    The operation is read-only with respect to the supplied MBA and source AST.
    It substitutes only compatible stack reads and returns ``None`` when no
    such fact exists, so normal root-only exploration remains unchanged.
    """

    environment = constant_environment_before_instruction(mba, block, instruction)
    if environment is None:
        return None

    def resolve_constant(leaf: Any) -> tuple[int, int] | None:
        try:
            import ida_hexrays
        except ImportError:
            return None
        mop = getattr(leaf, "mop", None)
        if isinstance(mop, MopSnapshot):
            try:
                mop = mop.to_mop(mba=mba)
            except Exception:
                return None
        if mop is None or mop.t != ida_hexrays.mop_S:
            return None
        name = constant_propagation_var_name(mop)
        value = environment.get(name) if name is not None else None
        if not isinstance(value, Const) or mop.size > value.size:
            return None
        if mop.size not in {1, 2, 4, 8}:
            return None
        return value.value, mop.size

    prepared_ast, substitutions = rewrite_ast_with_constant_resolver(
        ast,
        resolve_constant=resolve_constant,
    )
    if substitutions == 0:
        return None
    known_constants: dict[tuple[object, ...], int] = {}

    def collect_assumptions(node: Any) -> bool:
        if getattr(node, "is_leaf", lambda: False)():
            resolved = resolve_constant(node)
            if resolved is None:
                return True
            value, _size = resolved
            key = _live_leaf_key(node)
            if key is None:
                return False
            previous = known_constants.setdefault(key, value)
            return previous == value
        for child_name in ("left", "right", "dst"):
            child = getattr(node, child_name, None)
            if child is not None and not collect_assumptions(child):
                return False
        return True

    if not collect_assumptions(ast) or not known_constants:
        return None
    return PreparedCrossBlockAst(
        ast=prepared_ast,
        substitutions=substitutions,
        environment=environment,
        known_constants=MappingProxyType(known_constants),
    )


def _same_instruction(left: object, right: object) -> bool:
    """Use native object identity only; EA equality is intentionally unsafe."""

    if left is right:
        return True
    try:
        return bool(left == right)
    except Exception:
        return False


def _live_leaf_key(leaf: Any) -> tuple[object, ...] | None:
    """Return the same stable leaf key used by ``lower_hexrays_island``."""

    mop = getattr(leaf, "mop", None)
    if mop is None:
        return None
    try:
        cache_key = getattr(mop, "to_cache_key", None)
        raw_key = cache_key() if callable(cache_key) else None
        if raw_key is None:
            from d810.hexrays.expr import ast as runtime

            raw_key = runtime.get_mop_key(mop)
        key = ("mop", *tuple(raw_key))
        hash(key)
        return key
    except Exception:
        return None


__all__ = [
    "PreparedCrossBlockAst",
    "constant_environment_before_instruction",
    "prepare_ast_with_cross_block_constants",
    "rewrite_ast_with_constant_resolver",
]
