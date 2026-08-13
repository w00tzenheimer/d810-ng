"""Pure typed-term contracts for bounded Egglog MBA extraction.

The module deliberately imports no IDA or Egglog runtime at module load time.
Native AST types are resolved only when a native lowering function is called,
so budget, receipt, and term contracts remain usable in portable unit tests.
"""

from __future__ import annotations

import enum
import importlib
from collections.abc import Mapping
from dataclasses import dataclass

from d810.core.typing import Any


_AC_OPERATIONS = frozenset({"add", "and", "mul", "or", "xor"})
_UNARY_OPERATIONS = frozenset({"bnot", "neg"})
_BINARY_OPERATIONS = frozenset(
    {"add", "and", "mul", "or", "sub", "xor"}
)
_SUPPORTED_OPERATIONS = _UNARY_OPERATIONS | _BINARY_OPERATIONS
_VALID_DESTINATION_SIZES = frozenset({1, 2, 4, 8})


class ExtractionSkipReason(enum.StrEnum):
    """Stable wire values for successful no-op extraction outcomes."""

    EGGLOG_UNAVAILABLE = "egglog_unavailable"
    UNSUPPORTED_WIDTH_SEMANTICS = "unsupported_width_semantics"
    CANDIDATE_BUDGET = "candidate_budget"
    TIME_BUDGET = "time_budget"
    ECLASS_BUDGET = "eclass_budget"
    ENODE_BUDGET = "enode_budget"
    RULE_FIRING_BUDGET = "rule_firing_budget"
    NO_DEGREE_ELIGIBLE_IMPROVEMENT = "no_degree_eligible_improvement"
    LOWERING_FAILED = "lowering_failed"
    NATIVE_Z3_FAILED = "native_z3_failed"
    INTERNAL_ERROR = "internal_error"
    UNAVAILABLE_EGRAPH_STATISTICS = "unavailable_egraph_statistics"


def _positive_integer(name: str, value: object) -> None:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class EgglogExtractionBudget:
    """Hard limits for one fresh per-instruction saturation session."""

    max_leaves: int = 2
    max_operator_nodes: int = 10
    max_degree: int = 1
    saturation_rounds: int = 2
    max_eclasses: int = 64
    max_enodes: int = 128
    max_rule_firings: int = 32
    time_budget_ms: int = 3
    require_proof: bool = True

    def __post_init__(self) -> None:
        for name in (
            "max_leaves",
            "max_operator_nodes",
            "saturation_rounds",
            "max_eclasses",
            "max_enodes",
            "max_rule_firings",
            "time_budget_ms",
        ):
            _positive_integer(name, getattr(self, name))
        if type(self.max_degree) is not int or self.max_degree not in (1, 2):
            raise ValueError("max_degree must be exactly 1 or 2")
        if not 1 <= self.saturation_rounds <= 6:
            raise ValueError("saturation_rounds must be an integer from 1 to 6")
        if self.require_proof is not True:
            raise ValueError("require_proof must remain true")


@dataclass(frozen=True)
class EgglogExtractionReceipt:
    """Immutable telemetry for either an extraction or a fail-closed skip."""

    input_cost: tuple[int, int] | None = None
    extracted_cost: tuple[int, int] | None = None
    degree: int | None = None
    eclass_count: int | None = None
    enode_count: int | None = None
    rule_firings: int = 0
    elapsed_ms: float = 0.0
    selected_family: str | None = None
    selected_source: str | None = None
    selected_aliases: tuple[str, ...] = ()
    skip_reason: ExtractionSkipReason | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "selected_aliases", tuple(self.selected_aliases))
        if self.input_cost is not None:
            object.__setattr__(self, "input_cost", tuple(self.input_cost))
        if self.extracted_cost is not None:
            object.__setattr__(self, "extracted_cost", tuple(self.extracted_cost))


@dataclass(frozen=True)
class TypedBvTerm:
    """A fixed-width bit-vector term with constants or preserved live leaves."""

    operation: str | None
    width: int
    value: int | None = None
    leaf_key: tuple[object, ...] | None = None
    children: tuple[TypedBvTerm, ...] = ()

    def __post_init__(self) -> None:
        if type(self.width) is not int or self.width <= 0:
            raise ValueError("width must be a positive integer")
        object.__setattr__(self, "children", tuple(self.children))
        if self.leaf_key is not None:
            object.__setattr__(self, "leaf_key", tuple(self.leaf_key))

        if self.operation is None:
            if self.children:
                raise ValueError("leaf and constant terms cannot have children")
            if (self.value is None) == (self.leaf_key is None):
                raise ValueError(
                    "a terminal term must have exactly one of value or leaf_key"
                )
            if self.value is not None:
                if type(self.value) is not int:
                    raise ValueError("constant value must be an integer")
                mask = (1 << self.width) - 1
                object.__setattr__(self, "value", self.value & mask)
            else:
                if not self.leaf_key:
                    raise ValueError("leaf_key must not be empty")
                try:
                    hash(self.leaf_key)
                except TypeError as exc:
                    raise ValueError("leaf_key must be hashable") from exc
                try:
                    tuple(_leaf_key_part_fingerprint(part) for part in self.leaf_key)
                except ValueError as exc:
                    raise ValueError(
                        "leaf_key parts must be canonically representable"
                    ) from exc
            return

        if self.operation not in _SUPPORTED_OPERATIONS:
            raise ValueError(f"unsupported operation: {self.operation}")
        if self.value is not None or self.leaf_key is not None:
            raise ValueError("operator terms cannot carry a value or leaf_key")
        expected_arity = 1 if self.operation in _UNARY_OPERATIONS else 2
        if len(self.children) != expected_arity:
            raise ValueError(
                f"{self.operation} requires exactly {expected_arity} children"
            )
        if any(child.width != self.width for child in self.children):
            raise ValueError("operator children must have the same width")


def _leaf_key_part_fingerprint(value: object) -> tuple[object, ...]:
    """Return a totally ordered representation for stable live-leaf key parts."""

    if value is None:
        return ("none",)
    if type(value) is bool:
        return ("bool", int(value))
    if type(value) is int:
        return ("int", value)
    if type(value) is str:
        return ("str", value)
    if type(value) is bytes:
        return ("bytes", value.hex())
    if type(value) is tuple:
        return (
            "tuple",
            tuple(_leaf_key_part_fingerprint(item) for item in value),
        )
    raise ValueError(f"unsupported leaf-key part type: {type(value).__qualname__}")


def _term_fingerprint(term: TypedBvTerm) -> tuple[object, ...]:
    if term.operation is None and term.value is not None:
        return ("constant", term.width, term.value)
    if term.operation is None:
        assert term.leaf_key is not None
        return (
            "leaf",
            term.width,
            tuple(_leaf_key_part_fingerprint(part) for part in term.leaf_key),
        )
    return (
        "node",
        term.operation,
        term.width,
        tuple(_term_fingerprint(child) for child in term.children),
    )


def canonicalize_ac_term(term: TypedBvTerm) -> TypedBvTerm:
    """Canonicalize only homogeneous, same-width AC operator trees."""

    if term.operation is None:
        return term

    normalized_children = tuple(canonicalize_ac_term(child) for child in term.children)
    if term.operation not in _AC_OPERATIONS:
        return TypedBvTerm(
            operation=term.operation,
            width=term.width,
            children=normalized_children,
        )

    flattened: list[TypedBvTerm] = []

    def collect(child: TypedBvTerm) -> None:
        if child.operation == term.operation and child.width == term.width:
            for grandchild in child.children:
                collect(grandchild)
        else:
            flattened.append(child)

    for child in normalized_children:
        collect(child)
    flattened.sort(key=_term_fingerprint)

    rebuilt = flattened[0]
    for child in flattened[1:]:
        rebuilt = TypedBvTerm(
            operation=term.operation,
            width=term.width,
            children=(rebuilt, child),
        )
    return rebuilt


@dataclass(frozen=True)
class _NativeAstRuntime:
    AstNode: type[Any]
    AstLeaf: type[Any]
    AstConstant: type[Any]
    operation_by_opcode: Mapping[int, str]
    opcode_by_operation: Mapping[str, int]
    get_mop_key: Any


def _load_native_runtime() -> _NativeAstRuntime:
    """Resolve IDA-coupled AST types only at the native lowering boundary."""

    ida_hexrays = importlib.import_module("ida_hexrays")
    ast_module = importlib.import_module("d810.hexrays.expr.p_ast")
    opcode_by_operation = {
        "add": ida_hexrays.m_add,
        "and": ida_hexrays.m_and,
        "bnot": ida_hexrays.m_bnot,
        "mul": ida_hexrays.m_mul,
        "neg": ida_hexrays.m_neg,
        "or": ida_hexrays.m_or,
        "sub": ida_hexrays.m_sub,
        "xor": ida_hexrays.m_xor,
    }
    return _NativeAstRuntime(
        AstNode=ast_module.AstNode,
        AstLeaf=ast_module.AstLeaf,
        AstConstant=ast_module.AstConstant,
        operation_by_opcode={
            opcode: operation for operation, opcode in opcode_by_operation.items()
        },
        opcode_by_operation=opcode_by_operation,
        get_mop_key=ast_module.get_mop_key,
    )


def _native_width_witnesses(ast: Any) -> tuple[int, ...] | None:
    witnesses: list[int] = []
    for attribute in ("size", "expected_size", "dest_size"):
        try:
            value = getattr(ast, attribute, None)
        except Exception:
            return None
        if value is None:
            continue
        if type(value) is not int or value < 0:
            return None
        if value != 0:
            witnesses.append(value)
    return tuple(witnesses)


def _native_width_matches(
    ast: Any,
    destination_size: int,
    *,
    require_destination_witness: bool = False,
) -> bool:
    witnesses = _native_width_witnesses(ast)
    if witnesses is None or not witnesses:
        return False
    if require_destination_witness:
        destination_witness = getattr(ast, "dest_size", None)
        if type(destination_witness) is not int or destination_witness == 0:
            return False
    return all(witness == destination_size for witness in witnesses)


def _live_leaf_key(leaf: Any, runtime: _NativeAstRuntime) -> tuple[object, ...] | None:
    mop = getattr(leaf, "mop", None)
    if mop is None:
        return None
    try:
        to_cache_key = getattr(mop, "to_cache_key", None)
        raw_key = to_cache_key() if callable(to_cache_key) else runtime.get_mop_key(mop)
        key = tuple(raw_key)
        hash(key)
    except Exception:
        return None
    return ("mop", *key)


def _lower_native(
    ast: Any,
    *,
    destination_size: int,
    runtime: _NativeAstRuntime,
) -> TypedBvTerm | None:
    width = destination_size * 8
    if isinstance(ast, runtime.AstConstant):
        value = getattr(ast, "value", None)
        if type(value) is not int or not _native_width_matches(ast, destination_size):
            return None
        return TypedBvTerm(operation=None, width=width, value=value)
    if isinstance(ast, runtime.AstLeaf):
        if not _native_width_matches(ast, destination_size):
            return None
        leaf_key = _live_leaf_key(ast, runtime)
        if leaf_key is None:
            return None
        return TypedBvTerm(operation=None, width=width, leaf_key=leaf_key)
    if not isinstance(ast, runtime.AstNode):
        return None

    if not _native_width_matches(
        ast,
        destination_size,
        require_destination_witness=True,
    ):
        return None
    operation = runtime.operation_by_opcode.get(getattr(ast, "opcode", None))
    if operation is None or getattr(ast, "left", None) is None:
        return None
    left = _lower_native(
        ast.left,
        destination_size=destination_size,
        runtime=runtime,
    )
    if left is None:
        return None
    right_ast = getattr(ast, "right", None)
    if operation in _UNARY_OPERATIONS:
        if right_ast is not None:
            return None
        children = (left,)
    else:
        if right_ast is None:
            return None
        right = _lower_native(
            right_ast,
            destination_size=destination_size,
            runtime=runtime,
        )
        if right is None or right.width != left.width:
            return None
        children = (left, right)
    return TypedBvTerm(operation=operation, width=width, children=children)


def lower_native_ast_to_term(
    ast: Any,
    *,
    destination_size: int,
) -> TypedBvTerm | None:
    """Lower a width-preserving native AST, or fail closed with ``None``."""

    if type(destination_size) is not int or destination_size not in _VALID_DESTINATION_SIZES:
        return None
    try:
        runtime = _load_native_runtime()
        term = _lower_native(
            ast,
            destination_size=destination_size,
            runtime=runtime,
        )
        return None if term is None else canonicalize_ac_term(term)
    except Exception:
        return None


def _lower_term(
    term: TypedBvTerm,
    *,
    leafs: Mapping[tuple[object, ...], Any],
    destination_size: int,
    runtime: _NativeAstRuntime,
) -> Any | None:
    if term.width != destination_size * 8:
        return None
    if term.operation is None and term.value is not None:
        constant = runtime.AstConstant(str(term.value), term.value, destination_size)
        constant.dest_size = destination_size
        return constant
    if term.operation is None:
        assert term.leaf_key is not None
        leaf = leafs.get(term.leaf_key)
        if (
            not isinstance(leaf, runtime.AstLeaf)
            or isinstance(leaf, runtime.AstConstant)
            or not _native_width_matches(leaf, destination_size)
        ):
            return None
        if _live_leaf_key(leaf, runtime) != term.leaf_key:
            return None
        return leaf.clone()

    opcode = runtime.opcode_by_operation.get(term.operation)
    if opcode is None:
        return None
    rebuilt_children = tuple(
        _lower_term(
            child,
            leafs=leafs,
            destination_size=destination_size,
            runtime=runtime,
        )
        for child in term.children
    )
    if any(child is None for child in rebuilt_children):
        return None
    left = rebuilt_children[0]
    right = rebuilt_children[1] if len(rebuilt_children) == 2 else None
    node = runtime.AstNode(opcode, left, right)
    node.dest_size = destination_size
    return node


def lower_term_to_native_ast(
    term: TypedBvTerm,
    *,
    leafs: Mapping[tuple[object, ...], Any],
    destination_size: int,
) -> Any | None:
    """Rebuild a native operator tree from preserved leaves and constants."""

    if type(destination_size) is not int or destination_size not in _VALID_DESTINATION_SIZES:
        return None
    try:
        runtime = _load_native_runtime()
        rebuilt = _lower_term(
            term,
            leafs=leafs,
            destination_size=destination_size,
            runtime=runtime,
        )
        return rebuilt if isinstance(rebuilt, runtime.AstNode) else None
    except Exception:
        return None


__all__ = [
    "EgglogExtractionBudget",
    "EgglogExtractionReceipt",
    "ExtractionSkipReason",
    "TypedBvTerm",
    "canonicalize_ac_term",
    "lower_native_ast_to_term",
    "lower_term_to_native_ast",
]
