"""Pure typed-term contracts for bounded Egglog MBA extraction.

The module deliberately imports no IDA or Egglog runtime at module load time.
Native AST types are resolved only when a native lowering function is called,
so budget, receipt, and term contracts remain usable in portable unit tests.
"""

from __future__ import annotations

import enum
import importlib
import time
import json
from collections.abc import Mapping
from dataclasses import dataclass

from d810.core.typing import Any
from d810.backends.mba.egglog_statistics import (
    read_egraph_statistics,
    read_rule_firing_count,
)


_AC_OPERATIONS = frozenset({"add", "and", "mul", "or", "xor"})
_UNARY_OPERATIONS = frozenset({"bnot", "neg"})
_BINARY_OPERATIONS = frozenset({"add", "and", "mul", "or", "sub", "xor"})
_SUPPORTED_OPERATIONS = _UNARY_OPERATIONS | _BINARY_OPERATIONS
_VALID_DESTINATION_SIZES = frozenset({1, 2, 4, 8})

# Public capability contract.  This spike explores rewrites of the candidate
# root only; it does not recursively close over eligible nested subterms.
EGGLOG_EXPLORATION_SCOPE = "candidate-root-only"

# Egglog 13.2.0 exposes no interruptible or resource-capped run call. A reviewed
# single-rewrite run took 46 ms, so the live 3 ms default must never enter the
# Rust executor. Larger explicitly configured budgets reserve that observed
# baseline plus one millisecond per deterministic ground-graph work unit. This
# is deliberately conservative admission control, not a hard wall interrupt.
_MINIMUM_EGGLOG_RUN_BUDGET_MS = 50
_RUN_WORK_UNIT_BUDGET_MS = 1


try:
    _EGGLOG_MODULE = importlib.import_module("egglog")
except (ImportError, ModuleNotFoundError):
    _EGGLOG_MODULE = None
egglog = _EGGLOG_MODULE


if _EGGLOG_MODULE is not None:

    class BvExpr(egglog.Expr):
        """Width-carrying Egglog term for the bounded MBA adapter only."""

        @classmethod
        def leaf(
            cls,
            width: egglog.i64Like,
            key: egglog.StringLike,
        ) -> BvExpr: ...

        @classmethod
        def constant(
            cls,
            width: egglog.i64Like,
            value: egglog.i64Like,
        ) -> BvExpr: ...

        @classmethod
        def unary(
            cls,
            operation: egglog.StringLike,
            width: egglog.i64Like,
            operand: BvExpr,
        ) -> BvExpr: ...

        @classmethod
        def binary(
            cls,
            operation: egglog.StringLike,
            width: egglog.i64Like,
            left: BvExpr,
            right: BvExpr,
        ) -> BvExpr: ...

    class DegreeExpr(egglog.Expr):
        """Reachability wrapper whose integer tag is an exact rule degree."""

        @classmethod
        def at(
            cls,
            degree: egglog.i64Like,
            expression: BvExpr,
        ) -> DegreeExpr: ...

else:

    class BvExpr:  # pragma: no cover - exercised only without the optional extra.
        pass

    class DegreeExpr:  # pragma: no cover - exercised only without the optional extra.
        pass


def _load_egglog_module() -> Any | None:
    return _EGGLOG_MODULE


_monotonic = time.monotonic


class ExtractionSkipReason(enum.StrEnum):
    """Stable wire values for successful no-op extraction outcomes."""

    EGGLOG_UNAVAILABLE = "egglog_unavailable"
    UNSUPPORTED_WIDTH_SEMANTICS = "unsupported_width_semantics"
    NON_MBA_CANDIDATE = "non_mba_candidate"
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
    """Admission and acceptance limits for one fresh candidate session.

    ``time_budget_ms`` values below 50, including the live 3 ms default, are a
    safe telemetry/no-op mode: they prevent Egglog registration and execution.
    Larger values admit structurally capped work but cannot hard-interrupt an
    individual Egglog 13.2.0 Rust call.
    """

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
class EgglogExtractionResult:
    """One immutable candidate extraction outcome and its selected provenance."""

    replacement_ast: Any | None
    receipt: EgglogExtractionReceipt
    selected_provenance: tuple[str, str, tuple[str, ...]] | None = None

    def __post_init__(self) -> None:
        if self.selected_provenance is None:
            return
        family, source_name, aliases = self.selected_provenance
        object.__setattr__(
            self,
            "selected_provenance",
            (str(family), str(source_name), tuple(aliases)),
        )


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
                    _leaf_key_fingerprint(self.leaf_key)
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


def _leaf_key_fingerprint(
    leaf_key: tuple[object, ...],
) -> tuple[tuple[object, ...], ...]:
    return tuple(_leaf_key_part_fingerprint(part) for part in leaf_key)


def _term_fingerprint(term: TypedBvTerm) -> tuple[object, ...]:
    if term.operation is None and term.value is not None:
        return ("constant", term.width, term.value)
    if term.operation is None:
        assert term.leaf_key is not None
        return (
            "leaf",
            term.width,
            _leaf_key_fingerprint(term.leaf_key),
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
    AstProxy: type[Any]
    operation_by_opcode: Mapping[int, str]
    opcode_by_operation: Mapping[str, int]
    get_mop_key: Any


def _unwrap_runtime_ast_node(
    ast: Any,
    runtime: _NativeAstRuntime,
) -> Any | None:
    """Unwrap only known live AST proxies to a concrete operator root."""

    current = ast
    seen: set[int] = set()
    for _ in range(4):
        if type(current) is not runtime.AstProxy:
            return current if isinstance(current, runtime.AstNode) else None
        identity = id(current)
        if identity in seen:
            return None
        seen.add(identity)
        try:
            current = object.__getattribute__(current, "_target")
        except (AttributeError, TypeError):
            return None
    return None


def _load_native_runtime() -> _NativeAstRuntime:
    """Resolve IDA-coupled AST types only at the native lowering boundary."""

    ida_hexrays = importlib.import_module("ida_hexrays")
    ast_module = importlib.import_module("d810.hexrays.expr.ast")
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
        AstProxy=ast_module.AstProxy,
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
        live_key = ("mop", *key)
        _leaf_key_fingerprint(live_key)
    except Exception:
        return None
    return live_key


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

    if (
        type(destination_size) is not int
        or destination_size not in _VALID_DESTINATION_SIZES
    ):
        return None
    try:
        runtime = _load_native_runtime()
        ast = _unwrap_runtime_ast_node(ast, runtime)
        if ast is None:
            return None
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
        live_leaf_key = _live_leaf_key(leaf, runtime)
        if live_leaf_key is None or (
            _leaf_key_fingerprint(live_leaf_key) != _leaf_key_fingerprint(term.leaf_key)
        ):
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

    if (
        type(destination_size) is not int
        or destination_size not in _VALID_DESTINATION_SIZES
    ):
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


def _term_cost(term: TypedBvTerm) -> tuple[int, int]:
    if term.operation is None:
        return (0, 1)
    child_costs = tuple(_term_cost(child) for child in term.children)
    return (
        1 + sum(cost[0] for cost in child_costs),
        1 + sum(cost[1] for cost in child_costs),
    )


def _term_leafs(term: TypedBvTerm) -> frozenset[tuple[object, ...]]:
    if term.operation is None:
        return frozenset() if term.leaf_key is None else frozenset((term.leaf_key,))
    return frozenset().union(*(_term_leafs(child) for child in term.children))


def _collect_native_leafs(
    ast: Any,
    *,
    runtime: _NativeAstRuntime,
) -> dict[tuple[object, ...], Any] | None:
    leafs: dict[tuple[object, ...], Any] = {}

    def collect(node: Any) -> bool:
        if isinstance(node, runtime.AstConstant):
            return True
        if isinstance(node, runtime.AstLeaf):
            key = _live_leaf_key(node, runtime)
            if key is None:
                return False
            leafs.setdefault(key, node)
            return True
        if not isinstance(node, runtime.AstNode):
            return False
        left = getattr(node, "left", None)
        right = getattr(node, "right", None)
        return left is not None and collect(left) and (right is None or collect(right))

    return leafs if collect(ast) else None


def _leaf_key_string(leaf_key: tuple[object, ...]) -> str:
    return json.dumps(
        _leaf_key_fingerprint(leaf_key),
        ensure_ascii=True,
        separators=(",", ":"),
    )


def _egglog_integer(value: int, width: int) -> int:
    masked = value & ((1 << width) - 1)
    if masked >= (1 << 63):
        masked -= 1 << 64
    return masked


def _term_to_egglog(term: TypedBvTerm) -> Any:
    if term.operation is None and term.value is not None:
        return BvExpr.constant(term.width, _egglog_integer(term.value, term.width))
    if term.operation is None:
        assert term.leaf_key is not None
        return BvExpr.leaf(term.width, _leaf_key_string(term.leaf_key))
    children = tuple(_term_to_egglog(child) for child in term.children)
    if len(children) == 1:
        return BvExpr.unary(term.operation, term.width, children[0])
    return BvExpr.binary(
        term.operation,
        term.width,
        children[0],
        children[1],
    )


def _elapsed_ms(started: float) -> float:
    return max(0.0, (_monotonic() - started) * 1000.0)


def _egglog_term_work_units(term: TypedBvTerm) -> int:
    """Conservatively count constructor and literal nodes for one expression."""

    if term.operation is None:
        return 3
    return 1 + sum(_egglog_term_work_units(child) for child in term.children)


def _degree_expression_work_units(term: TypedBvTerm) -> int:
    return 2 + _egglog_term_work_units(term)


def _degree_expression_work_unit_keys(
    degree: int, term: TypedBvTerm
) -> frozenset[tuple[object, ...]]:
    """Identify shared registered structure once, as Egglog's graph does."""

    keys: set[tuple[object, ...]] = {
        ("degree", degree, "constructor"),
        ("degree", degree, "literal"),
    }

    def visit(node: TypedBvTerm) -> None:
        keys.add(("term", degree, node))
        if node.operation is None:
            keys.add(("term-width", degree, node.width))
            keys.add(("term-literal", degree, node.value, node.leaf_key))
        for child in node.children:
            visit(child)

    visit(term)
    return frozenset(keys)


def _pre_run_time_guard(
    *,
    started: float,
    budget: EgglogExtractionBudget,
    work_units: int,
) -> tuple[bool, float]:
    """Admit a bounded run workload only while deterministic headroom remains."""

    elapsed = _elapsed_ms(started)
    remaining_ms = max(0.0, budget.time_budget_ms - elapsed)
    required_ms = _MINIMUM_EGGLOG_RUN_BUDGET_MS + work_units * _RUN_WORK_UNIT_BUDGET_MS
    return (required_ms <= remaining_ms, elapsed)


def _extraction_result(
    *,
    started: float,
    input_cost: tuple[int, int] | None,
    extracted_cost: tuple[int, int] | None = None,
    degree: int | None = None,
    eclass_count: int | None = None,
    enode_count: int | None = None,
    rule_firings: int = 0,
    provenance: tuple[str, str, tuple[str, ...]] | None = None,
    replacement_ast: Any | None = None,
    skip_reason: ExtractionSkipReason | None = None,
    elapsed_ms: float | None = None,
) -> EgglogExtractionResult:
    elapsed = _elapsed_ms(started) if elapsed_ms is None else elapsed_ms
    family = provenance[0] if provenance is not None else None
    source_name = provenance[1] if provenance is not None else None
    aliases = provenance[2] if provenance is not None else ()
    return EgglogExtractionResult(
        replacement_ast=replacement_ast,
        receipt=EgglogExtractionReceipt(
            input_cost=input_cost,
            extracted_cost=extracted_cost,
            degree=degree,
            eclass_count=eclass_count,
            enode_count=enode_count,
            rule_firings=rule_firings,
            elapsed_ms=elapsed,
            selected_family=family,
            selected_source=source_name,
            selected_aliases=aliases,
            skip_reason=skip_reason,
        ),
        selected_provenance=provenance,
    )


@dataclass(frozen=True)
class _ReachableCandidate:
    degree: int
    term: TypedBvTerm
    family: str
    source_name: str
    aliases: tuple[str, ...]
    expression: Any
    rule_decl: Any
    catalogue_index: int

    @property
    def provenance(self) -> tuple[str, str, tuple[str, ...]]:
        return (self.family, self.source_name, self.aliases)


def _extraction_selection_key(
    candidate: _ReachableCandidate,
    candidate_cost: tuple[int, int],
) -> tuple[int, int, int, int]:
    """Rank equal candidates by their checked-in catalogue declaration order."""

    return (*candidate_cost, candidate.degree, candidate.catalogue_index)


def extract_bounded_candidate(
    candidate_ast: Any,
    rules: Any,
    budget: EgglogExtractionBudget,
    destination_size: int,
) -> EgglogExtractionResult:
    """Extract one strictly cheaper candidate through exact catalogue layers.

    One fresh e-graph is created for every invocation where Egglog is
    available. Exploration is candidate-root-only; eligible nested subterms
    are not traversed or claimed. Host-side grounding evaluates only the
    already-admitted compiler constraints.

    Egglog 13.2.0 cannot interrupt an individual Rust run. The time field is
    therefore an acceptance deadline plus a strict pre-run workload guard, not
    a hard wall-clock interrupt. Frontier construction is cooperative, all
    graph/firing caps are enforced before registration, and only one bounded
    schedule round is submitted at a time.
    """

    try:
        started = _monotonic()
    except Exception:
        started = 0.0
    input_cost: tuple[int, int] | None = None
    egglog = _load_egglog_module()
    if egglog is None or _EGGLOG_MODULE is None:
        return _extraction_result(
            started=started,
            input_cost=None,
            skip_reason=ExtractionSkipReason.EGGLOG_UNAVAILABLE,
            elapsed_ms=0.0,
        )

    try:
        egraph = egglog.EGraph()
        term = lower_native_ast_to_term(
            candidate_ast,
            destination_size=destination_size,
        )
        if term is None:
            return _extraction_result(
                started=started,
                input_cost=None,
                skip_reason=ExtractionSkipReason.UNSUPPORTED_WIDTH_SEMANTICS,
            )
        input_cost = _term_cost(term)
        if input_cost[0] > budget.max_operator_nodes:
            return _extraction_result(
                started=started,
                input_cost=input_cost,
                skip_reason=ExtractionSkipReason.CANDIDATE_BUDGET,
            )
        if len(_term_leafs(term)) > budget.max_leaves:
            return _extraction_result(
                started=started,
                input_cost=input_cost,
                skip_reason=ExtractionSkipReason.CANDIDATE_BUDGET,
            )
        elapsed = _elapsed_ms(started)
        if elapsed > budget.time_budget_ms:
            return _extraction_result(
                started=started,
                input_cost=input_cost,
                skip_reason=ExtractionSkipReason.TIME_BUDGET,
                elapsed_ms=elapsed,
            )

        runtime = _load_native_runtime()
        concrete_candidate = _unwrap_runtime_ast_node(candidate_ast, runtime)
        native_leafs = (
            None
            if concrete_candidate is None
            else _collect_native_leafs(concrete_candidate, runtime=runtime)
        )
        if native_leafs is None:
            return _extraction_result(
                started=started,
                input_cost=input_cost,
                skip_reason=ExtractionSkipReason.LOWERING_FAILED,
            )

        from d810.backends.mba.egglog_add_rule_compiler import (
            apply_compiled_rule_to_term,
        )

        ordered_rules = tuple(rules)
        frontier: dict[int, tuple[TypedBvTerm, ...]] = {0: (term,)}
        reachable: list[_ReachableCandidate] = []
        rewrites: list[Any] = []
        registration_work_unit_keys = set(_degree_expression_work_unit_keys(0, term))
        for degree in range(budget.max_degree):
            next_terms: dict[TypedBvTerm, None] = {}
            for source_term in frontier.get(degree, ()):
                for catalogue_index, rule in enumerate(ordered_rules):
                    elapsed = _elapsed_ms(started)
                    if elapsed > budget.time_budget_ms:
                        return _extraction_result(
                            started=started,
                            input_cost=input_cost,
                            skip_reason=ExtractionSkipReason.TIME_BUDGET,
                            elapsed_ms=elapsed,
                        )
                    replacement = apply_compiled_rule_to_term(rule, source_term)
                    if replacement is None:
                        continue
                    replacement = canonicalize_ac_term(replacement)
                    elapsed = _elapsed_ms(started)
                    if elapsed > budget.time_budget_ms:
                        return _extraction_result(
                            started=started,
                            input_cost=input_cost,
                            skip_reason=ExtractionSkipReason.TIME_BUDGET,
                            elapsed_ms=elapsed,
                        )
                    if len(rewrites) + 1 > budget.max_rule_firings:
                        return _extraction_result(
                            started=started,
                            input_cost=input_cost,
                            skip_reason=ExtractionSkipReason.RULE_FIRING_BUDGET,
                        )
                    projected_work_unit_keys = registration_work_unit_keys | set(
                        _degree_expression_work_unit_keys(degree, source_term)
                    ) | set(
                        _degree_expression_work_unit_keys(degree + 1, replacement)
                    )
                    projected_work_units = len(projected_work_unit_keys)
                    if projected_work_units > budget.max_eclasses:
                        return _extraction_result(
                            started=started,
                            input_cost=input_cost,
                            skip_reason=ExtractionSkipReason.ECLASS_BUDGET,
                        )
                    if projected_work_units > budget.max_enodes:
                        return _extraction_result(
                            started=started,
                            input_cost=input_cost,
                            skip_reason=ExtractionSkipReason.ENODE_BUDGET,
                        )
                    source_expression = DegreeExpr.at(
                        degree,
                        _term_to_egglog(source_term),
                    )
                    target_expression = DegreeExpr.at(
                        degree + 1,
                        _term_to_egglog(replacement),
                    )
                    executable_rewrite = egglog.rewrite(source_expression).to(
                        target_expression
                    )
                    rewrites.append(executable_rewrite)
                    reachable.append(
                        _ReachableCandidate(
                            degree=degree + 1,
                            term=replacement,
                            family=str(rule.family),
                            source_name=str(rule.source_name),
                            aliases=tuple(rule.aliases),
                            expression=target_expression,
                            rule_decl=executable_rewrite.decl,
                            catalogue_index=catalogue_index,
                        )
                    )
                    next_terms[replacement] = None
                    registration_work_unit_keys = projected_work_unit_keys
            frontier[degree + 1] = tuple(next_terms)

        registration_work_units = len(registration_work_unit_keys)
        scheduled_work_units = registration_work_units + (
            len(rewrites) * budget.saturation_rounds
        )
        admitted, elapsed = _pre_run_time_guard(
            started=started,
            budget=budget,
            work_units=scheduled_work_units,
        )
        if not admitted:
            return _extraction_result(
                started=started,
                input_cost=input_cost,
                skip_reason=ExtractionSkipReason.TIME_BUDGET,
                elapsed_ms=elapsed,
            )
        seed = DegreeExpr.at(0, _term_to_egglog(term))
        egraph.register(seed, *rewrites)
        matches_per_rule: dict[Any, int] = {}
        eclass_count = 0
        enode_count = 0
        for _round in range(budget.saturation_rounds):
            admitted, elapsed = _pre_run_time_guard(
                started=started,
                budget=budget,
                work_units=registration_work_units + len(rewrites),
            )
            if not admitted:
                return _extraction_result(
                    started=started,
                    input_cost=input_cost,
                    rule_firings=sum(matches_per_rule.values()),
                    skip_reason=ExtractionSkipReason.TIME_BUDGET,
                    elapsed_ms=elapsed,
                )
            round_report = egraph.run(1)
            round_firings = read_rule_firing_count(round_report)
            statistics = read_egraph_statistics(egraph)
            elapsed = _elapsed_ms(started)
            if elapsed > budget.time_budget_ms:
                return _extraction_result(
                    started=started,
                    input_cost=input_cost,
                    rule_firings=sum(matches_per_rule.values()) + (round_firings or 0),
                    skip_reason=ExtractionSkipReason.TIME_BUDGET,
                    elapsed_ms=elapsed,
                )
            if round_firings is None or statistics is None:
                return _extraction_result(
                    started=started,
                    input_cost=input_cost,
                    rule_firings=sum(matches_per_rule.values()) + (round_firings or 0),
                    skip_reason=ExtractionSkipReason.UNAVAILABLE_EGRAPH_STATISTICS,
                    elapsed_ms=elapsed,
                )
            for declaration, count in round_report.num_matches_per_rule.items():
                matches_per_rule[declaration] = (
                    matches_per_rule.get(declaration, 0) + count
                )
            eclass_count, enode_count = statistics
            current_firings = sum(matches_per_rule.values())
            if eclass_count > budget.max_eclasses:
                return _extraction_result(
                    started=started,
                    input_cost=input_cost,
                    eclass_count=eclass_count,
                    enode_count=enode_count,
                    rule_firings=current_firings,
                    skip_reason=ExtractionSkipReason.ECLASS_BUDGET,
                )
            if enode_count > budget.max_enodes:
                return _extraction_result(
                    started=started,
                    input_cost=input_cost,
                    eclass_count=eclass_count,
                    enode_count=enode_count,
                    rule_firings=current_firings,
                    skip_reason=ExtractionSkipReason.ENODE_BUDGET,
                )
            if current_firings > budget.max_rule_firings:
                return _extraction_result(
                    started=started,
                    input_cost=input_cost,
                    eclass_count=eclass_count,
                    enode_count=enode_count,
                    rule_firings=current_firings,
                    skip_reason=ExtractionSkipReason.RULE_FIRING_BUDGET,
                )
            if not getattr(round_report, "updated", True):
                break
        rule_firings = sum(matches_per_rule.values())
        report = type(
            "_AggregateRunReport",
            (),
            {"num_matches_per_rule": matches_per_rule},
        )()
        common = {
            "started": started,
            "input_cost": input_cost,
            "eclass_count": eclass_count,
            "enode_count": enode_count,
            "rule_firings": rule_firings,
        }
        if eclass_count > budget.max_eclasses:
            return _extraction_result(
                **common,
                skip_reason=ExtractionSkipReason.ECLASS_BUDGET,
            )
        if enode_count > budget.max_enodes:
            return _extraction_result(
                **common,
                skip_reason=ExtractionSkipReason.ENODE_BUDGET,
            )
        if rule_firings > budget.max_rule_firings:
            return _extraction_result(
                **common,
                skip_reason=ExtractionSkipReason.RULE_FIRING_BUDGET,
            )

        selections: list[
            tuple[
                tuple[int, int, int, int],
                Any,
                _ReachableCandidate,
            ]
        ] = []
        for candidate in reachable:
            if report.num_matches_per_rule.get(candidate.rule_decl, 0) <= 0:
                continue
            try:
                egraph.extract(candidate.expression)
            except egglog.EggSmolError:
                continue
            candidate_cost = _term_cost(candidate.term)
            if candidate_cost >= input_cost:
                continue
            rebuilt = lower_term_to_native_ast(
                candidate.term,
                leafs=native_leafs,
                destination_size=destination_size,
            )
            if rebuilt is None:
                continue
            selections.append(
                (
                    _extraction_selection_key(candidate, candidate_cost),
                    rebuilt,
                    candidate,
                )
            )
        if not selections:
            return _extraction_result(
                **common,
                skip_reason=ExtractionSkipReason.NO_DEGREE_ELIGIBLE_IMPROVEMENT,
            )
        selection_key, replacement_ast, selected = min(
            selections,
            key=lambda item: item[0],
        )
        elapsed = _elapsed_ms(started)
        if elapsed > budget.time_budget_ms:
            return _extraction_result(
                **common,
                skip_reason=ExtractionSkipReason.TIME_BUDGET,
                elapsed_ms=elapsed,
            )
        return _extraction_result(
            **common,
            extracted_cost=(selection_key[0], selection_key[1]),
            degree=selected.degree,
            provenance=selected.provenance,
            replacement_ast=replacement_ast,
        )
    except Exception:
        try:
            elapsed = _elapsed_ms(started)
        except Exception:
            elapsed = 0.0
        return _extraction_result(
            started=started,
            input_cost=input_cost,
            skip_reason=ExtractionSkipReason.INTERNAL_ERROR,
            elapsed_ms=elapsed,
        )


__all__ = [
    "BvExpr",
    "DegreeExpr",
    "EGGLOG_EXPLORATION_SCOPE",
    "EgglogExtractionBudget",
    "EgglogExtractionReceipt",
    "EgglogExtractionResult",
    "ExtractionSkipReason",
    "TypedBvTerm",
    "canonicalize_ac_term",
    "extract_bounded_candidate",
    "lower_native_ast_to_term",
    "lower_term_to_native_ast",
]
