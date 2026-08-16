"""Read a fixed-width MBA island directly from live ``minsn_t``/``mop_t``.

This backend adapter deliberately avoids ``minsn_to_ast()`` and the portable
``d810.ir`` operand projections.  It reads a candidate instruction only long
enough to construct an immutable, callback-local view; callers materialize a
portable term or an AST only after a certified native match requires one.
"""

from __future__ import annotations

import importlib
import json
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from d810.core.typing import Any
from d810.mba.island_profile import IslandBlocker, MbaIslandClass, MbaIslandProfile
from d810.mba.typed_term import TypedBvTerm, _leaf_key_fingerprint


_VALID_DESTINATION_SIZES = frozenset({1, 2, 4, 8})
_UNARY_OPERATIONS = frozenset({"bnot", "neg"})
_BOOLEAN_OPERATIONS = frozenset({"and", "bnot", "or", "xor"})
_ARITHMETIC_OPERATIONS = frozenset({"add", "mul", "neg", "sub"})
_AC_OPERATIONS = frozenset({"add", "and", "mul", "or", "xor"})


@dataclass(frozen=True)
class NativeMopRuntime:
    """Minimal live-microcode vocabulary, injectable only for portable tests."""

    mop_z: int
    mop_n: int
    mop_d: int
    leaf_kinds: frozenset[int]
    operation_by_opcode: Mapping[int, str]
    blocker_by_opcode: Mapping[int, IslandBlocker]
    get_mop_key: Callable[[Any], object]


@dataclass(frozen=True)
class NativeMbaTermView:
    """One immutable direct view of a same-width live microcode expression."""

    operation: str | None
    width: int
    constant_value: int | None = None
    leaf_key: tuple[object, ...] | None = None
    children: tuple[NativeMbaTermView, ...] = ()
    native_operand: Any | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "children", tuple(self.children))
        if self.operation is None:
            if self.children or (self.constant_value is None) == (
                self.leaf_key is None
            ):
                raise ValueError("native terminal must have one value or leaf key")
            return
        if self.constant_value is not None or self.leaf_key is not None:
            raise ValueError("native operation cannot carry terminal data")
        expected_arity = 1 if self.operation in _UNARY_OPERATIONS else 2
        if len(self.children) != expected_arity:
            raise ValueError(f"{self.operation} requires {expected_arity} children")
        if any(child.width != self.width for child in self.children):
            raise ValueError("native operation children must have the same width")

    @property
    def term_cost(self) -> tuple[int, int]:
        if self.operation is None:
            return (0, 1)
        child_costs = tuple(child.term_cost for child in self.children)
        return (
            1 + sum(cost[0] for cost in child_costs),
            1 + sum(cost[1] for cost in child_costs),
        )

    def canonical_children(self) -> tuple[NativeMbaTermView, ...]:
        """Return free AC order without mutating the native operand tree."""

        if self.operation not in _AC_OPERATIONS:
            return self.children
        flattened: list[NativeMbaTermView] = []

        def collect(view: NativeMbaTermView) -> None:
            if view.operation == self.operation and view.width == self.width:
                for child in view.children:
                    collect(child)
            else:
                flattened.append(view)

        for child in self.children:
            collect(child)
        return tuple(sorted(flattened, key=_view_sort_key))

    def to_typed_term(self) -> TypedBvTerm:
        """Materialize portable semantics only after an admitted native match."""

        if self.operation is None:
            if self.constant_value is not None:
                return TypedBvTerm(None, self.width, value=self.constant_value)
            assert self.leaf_key is not None
            return TypedBvTerm(None, self.width, leaf_key=self.leaf_key)
        return TypedBvTerm(
            self.operation,
            self.width,
            children=tuple(child.to_typed_term() for child in self.children),
        )

    @classmethod
    def from_instruction(
        cls,
        instruction: Any,
        *,
        destination_size: int,
        runtime: NativeMopRuntime | None = None,
    ) -> NativeMbaViewResult:
        """Read one direct minsn/mop tree, returning an immutable failure profile."""

        if (
            type(destination_size) is not int
            or destination_size not in _VALID_DESTINATION_SIZES
        ):
            return _unsupported_result(destination_size, {IslandBlocker.MIXED_WIDTH})
        try:
            active_runtime = (
                runtime if runtime is not None else _load_live_mop_runtime()
            )
            view, blockers = _read_instruction(
                instruction,
                destination_size=destination_size,
                runtime=active_runtime,
                seen_instructions=set(),
            )
        except Exception:
            return _unsupported_result(
                destination_size, {IslandBlocker.UNSUPPORTED_OPCODE}
            )
        if view is None:
            return _unsupported_result(destination_size, blockers)
        return NativeMbaViewResult(view=view, profile=_profile_view(view))


@dataclass(frozen=True)
class NativeMbaViewResult:
    view: NativeMbaTermView | None
    profile: MbaIslandProfile


def semantic_native_leaf_key(mop: Any) -> tuple[object, ...]:
    """Return one runtime-independent identity for an admitted native leaf.

    Python and Cython AST implementations use different cache-key encodings,
    but native proof terms need the same identity on both sides of delayed AST
    construction. These three leaf kinds have exact location identities that
    do not depend on transient SSA ``valnum`` values or wrapper object IDs.
    """

    ida_hexrays = importlib.import_module("ida_hexrays")
    kind = getattr(mop, "t", None)
    size = getattr(mop, "size", None)
    if type(size) is not int:
        raise ValueError("native MBA leaf is missing its width")
    if kind == ida_hexrays.mop_r:
        return (kind, size, mop.r)
    if kind == ida_hexrays.mop_S:
        stack = getattr(mop, "s", None)
        if stack is None:
            raise ValueError("stack operand is missing its stack slot")
        return (kind, size, stack.off)
    if kind == ida_hexrays.mop_v:
        return (kind, size, mop.g)
    raise ValueError("unsupported direct native MBA leaf kind")


def _load_live_mop_runtime() -> NativeMopRuntime:
    """Resolve only the direct Hex-Rays SDK names used by this backend adapter."""

    ida_hexrays = importlib.import_module("ida_hexrays")
    operations = {
        getattr(ida_hexrays, f"m_{name}"): name
        for name in ("add", "and", "bnot", "mul", "neg", "or", "sub", "xor")
    }
    blockers: dict[int, IslandBlocker] = {}
    for name, blocker in (
        ("m_xdu", IslandBlocker.CAST),
        ("m_xds", IslandBlocker.CAST),
        ("m_low", IslandBlocker.CAST),
        ("m_high", IslandBlocker.CAST),
        ("m_shl", IslandBlocker.AMBIGUOUS_SHIFT),
        ("m_shr", IslandBlocker.AMBIGUOUS_SHIFT),
        ("m_sar", IslandBlocker.AMBIGUOUS_SHIFT),
        ("m_ldx", IslandBlocker.LOAD),
        ("m_call", IslandBlocker.CALL),
        ("m_icall", IslandBlocker.CALL),
    ):
        opcode = getattr(ida_hexrays, name, None)
        if type(opcode) is int:
            blockers[opcode] = blocker

    return NativeMopRuntime(
        mop_z=ida_hexrays.mop_z,
        mop_n=ida_hexrays.mop_n,
        mop_d=ida_hexrays.mop_d,
        leaf_kinds=frozenset(
            getattr(ida_hexrays, name)
            for name in ("mop_r", "mop_S", "mop_v")
            if type(getattr(ida_hexrays, name, None)) is int
        ),
        operation_by_opcode=MappingProxyType(operations),
        blocker_by_opcode=MappingProxyType(blockers),
        get_mop_key=semantic_native_leaf_key,
    )


def _read_instruction(
    instruction: Any,
    *,
    destination_size: int,
    runtime: NativeMopRuntime,
    seen_instructions: set[int],
) -> tuple[NativeMbaTermView | None, set[IslandBlocker]]:
    identity = id(instruction)
    if identity in seen_instructions:
        return None, {IslandBlocker.UNSUPPORTED_OPCODE}
    seen_instructions.add(identity)
    try:
        destination = getattr(instruction, "d", None)
        if not _has_exact_width(destination, destination_size):
            return None, {IslandBlocker.MIXED_WIDTH}
        operation = runtime.operation_by_opcode.get(
            getattr(instruction, "opcode", None)
        )
        if operation is None:
            blocker = runtime.blocker_by_opcode.get(
                getattr(instruction, "opcode", None), IslandBlocker.UNSUPPORTED_OPCODE
            )
            return None, {blocker}
        left, left_blockers = _read_operand(
            getattr(instruction, "l", None),
            destination_size=destination_size,
            runtime=runtime,
            seen_instructions=seen_instructions,
        )
        if left is None:
            return None, left_blockers
        if operation in _UNARY_OPERATIONS:
            right = getattr(instruction, "r", None)
            if (
                right is not None
                and getattr(right, "t", runtime.mop_z) != runtime.mop_z
            ):
                return None, {IslandBlocker.UNSUPPORTED_OPCODE}
            return NativeMbaTermView(
                operation, destination_size * 8, children=(left,)
            ), set()
        right, right_blockers = _read_operand(
            getattr(instruction, "r", None),
            destination_size=destination_size,
            runtime=runtime,
            seen_instructions=seen_instructions,
        )
        if right is None:
            return None, right_blockers
        return (
            NativeMbaTermView(operation, destination_size * 8, children=(left, right)),
            set(),
        )
    finally:
        seen_instructions.discard(identity)


def _read_operand(
    operand: Any,
    *,
    destination_size: int,
    runtime: NativeMopRuntime,
    seen_instructions: set[int],
) -> tuple[NativeMbaTermView | None, set[IslandBlocker]]:
    if operand is None or not _has_exact_width(operand, destination_size):
        return None, {IslandBlocker.MIXED_WIDTH}
    kind = getattr(operand, "t", None)
    width = destination_size * 8
    if kind == runtime.mop_n:
        number = getattr(getattr(operand, "nnn", None), "value", None)
        if type(number) is not int:
            return None, {IslandBlocker.UNSUPPORTED_OPCODE}
        return NativeMbaTermView(
            None,
            width,
            constant_value=number & ((1 << width) - 1),
            native_operand=operand,
        ), set()
    if kind == runtime.mop_d:
        nested = getattr(operand, "d", None)
        if nested is None:
            return None, {IslandBlocker.UNSUPPORTED_OPCODE}
        return _read_instruction(
            nested,
            destination_size=destination_size,
            runtime=runtime,
            seen_instructions=seen_instructions,
        )
    if kind == runtime.mop_z:
        return None, {IslandBlocker.UNSUPPORTED_OPCODE}
    if kind not in runtime.leaf_kinds:
        return None, {IslandBlocker.UNSUPPORTED_OPCODE}
    try:
        raw_key = runtime.get_mop_key(operand)
        key = ("mop", *tuple(raw_key))
        _leaf_key_fingerprint(key)
    except Exception:
        return None, {IslandBlocker.UNSUPPORTED_OPCODE}
    return NativeMbaTermView(None, width, leaf_key=key, native_operand=operand), set()


def _has_exact_width(value: Any, destination_size: int) -> bool:
    return type(getattr(value, "size", None)) is int and value.size == destination_size


def _view_sort_key(view: NativeMbaTermView) -> tuple[object, ...]:
    if view.operation is None and view.constant_value is not None:
        return ("constant", view.width, view.constant_value)
    if view.operation is None:
        assert view.leaf_key is not None
        return ("leaf", view.width, _leaf_key_fingerprint(view.leaf_key))
    return (
        "node",
        view.operation,
        view.width,
        tuple(_view_sort_key(child) for child in view.canonical_children()),
    )


def _unsupported_result(
    destination_size: int, blockers: set[IslandBlocker]
) -> NativeMbaViewResult:
    width_bits = max(1, destination_size if type(destination_size) is int else 1) * 8
    normalized = tuple(sorted(blockers, key=str))
    return NativeMbaViewResult(
        view=None,
        profile=MbaIslandProfile(
            width_bits=width_bits,
            operator_count=0,
            total_node_count=1,
            distinct_leaf_count=0,
            constant_count=0,
            operations=(),
            has_boolean=False,
            has_arithmetic=False,
            nonlinear_product_count=0,
            island_class=MbaIslandClass.UNSUPPORTED,
            blockers=normalized,
            fingerprint=json.dumps(("unsupported", width_bits), separators=(",", ":")),
        ),
    )


def _profile_view(view: NativeMbaTermView) -> MbaIslandProfile:
    operations: Counter[str] = Counter()
    leafs: set[tuple[object, ...]] = set()
    constants = 0
    nonlinear_products = 0

    def contains_leaf(node: NativeMbaTermView) -> bool:
        if node.operation is None:
            return node.leaf_key is not None
        return any(contains_leaf(child) for child in node.children)

    def visit(node: NativeMbaTermView) -> None:
        nonlocal constants, nonlinear_products
        if node.operation is None:
            if node.leaf_key is None:
                constants += 1
            else:
                leafs.add(node.leaf_key)
            return
        operations[node.operation] += 1
        if node.operation == "mul" and all(
            contains_leaf(child) for child in node.children
        ):
            nonlinear_products += 1
        for child in node.children:
            visit(child)

    visit(view)
    has_boolean = any(operation in _BOOLEAN_OPERATIONS for operation in operations)
    has_arithmetic = any(
        operation in _ARITHMETIC_OPERATIONS for operation in operations
    )
    if nonlinear_products:
        island_class = MbaIslandClass.NONLINEAR_MBA
    elif has_boolean and has_arithmetic:
        island_class = MbaIslandClass.LINEAR_MBA
    else:
        island_class = MbaIslandClass.NOT_MBA
    operator_count, total_node_count = view.term_cost
    return MbaIslandProfile(
        width_bits=view.width,
        operator_count=operator_count,
        total_node_count=total_node_count,
        distinct_leaf_count=len(leafs),
        constant_count=constants,
        operations=tuple(sorted(operations.items())),
        has_boolean=has_boolean,
        has_arithmetic=has_arithmetic,
        nonlinear_product_count=nonlinear_products,
        island_class=island_class,
        blockers=(),
        fingerprint=json.dumps(
            _view_sort_key(view), ensure_ascii=True, separators=(",", ":")
        ),
    )


__all__ = ["NativeMbaTermView", "NativeMbaViewResult", "NativeMopRuntime"]
