from __future__ import annotations

from dataclasses import FrozenInstanceError, dataclass, fields, replace
from types import SimpleNamespace

import pytest

from d810.backends.mba import egglog_add_rule_compiler, egglog_saturation
from d810.backends.mba import hexrays_island
from d810.backends.mba import egglog_statistics
from d810.backends.mba.egglog_add_rule_compiler import (
    CERTIFICATE_WIDTHS,
    CompiledEgglogRule,
    _compile_rule_families,
    apply_compiled_rule_to_term,
)
from d810.backends.mba.egglog_saturation import (
    EgglogExtractionBudget,
    EgglogExtractionReceipt,
    EgglogExtractionResult,
    ExtractionSkipReason,
    TypedBvTerm,
    canonicalize_ac_term,
    extract_bounded_candidate,
    lower_native_ast_to_term,
    lower_term_to_native_ast,
)
from d810.mba import typed_term
from d810.mba.rules._base import VerifiableRule
from d810.mba.rules.xor import Xor_NestedStuff


def _leaf(name: str, *, width: int = 32) -> TypedBvTerm:
    return TypedBvTerm(operation=None, width=width, leaf_key=("register", name))


def _constant(value: int, *, width: int = 32) -> TypedBvTerm:
    return TypedBvTerm(operation=None, width=width, value=value)


def _node(
    operation: str,
    left: TypedBvTerm,
    right: TypedBvTerm | None = None,
    *,
    width: int = 32,
) -> TypedBvTerm:
    children = (left,) if right is None else (left, right)
    return TypedBvTerm(operation=operation, width=width, children=children)


def _term_from_symbolic(expression, bindings=None, *, width: int = 32):
    bindings = {} if bindings is None else bindings
    if expression.operation is None:
        if expression.value is not None:
            return _constant(int(expression.value), width=width)
        assert expression.name is not None
        return bindings.setdefault(expression.name, _leaf(expression.name, width=width))
    left = _term_from_symbolic(expression.left, bindings, width=width)
    right = (
        _term_from_symbolic(expression.right, bindings, width=width)
        if expression.right is not None
        else None
    )
    return canonicalize_ac_term(_node(expression.operation, left, right, width=width))


def test_ac_canonicalization_matches_swapped_operands_without_rewrite_rules():
    a = _leaf("a")
    b = _leaf("b")

    assert canonicalize_ac_term(_node("add", a, b)) == canonicalize_ac_term(
        _node("add", b, a)
    )


@pytest.mark.parametrize("operation", ["add", "mul", "and", "or", "xor"])
def test_ac_canonicalization_flattens_same_width_association(operation: str):
    a = _leaf("a")
    b = _leaf("b")
    c = _leaf("c")

    left_associated = _node(operation, _node(operation, a, b), c)
    permuted_right_associated = _node(operation, a, _node(operation, c, b))

    assert canonicalize_ac_term(left_associated) == canonicalize_ac_term(
        permuted_right_associated
    )


def test_non_ac_operations_keep_operand_order():
    a = _leaf("a")
    b = _leaf("b")

    assert canonicalize_ac_term(_node("sub", a, b)) != canonicalize_ac_term(
        _node("sub", b, a)
    )


def test_equal_cost_extraction_tie_uses_catalogue_declaration_order_not_name():
    alphabetically_earlier = egglog_saturation._ReachableCandidate(
        degree=1,
        term=_leaf("a"),
        family="add",
        source_name="AardvarkRule",
        aliases=(),
        expression=object(),
        rule_decl=object(),
        catalogue_index=1,
    )
    declared_earlier = egglog_saturation._ReachableCandidate(
        degree=1,
        term=_leaf("z"),
        family="xor",
        source_name="ZuluRule",
        aliases=(),
        expression=object(),
        rule_decl=object(),
        catalogue_index=0,
    )

    selected = min(
        (alphabetically_earlier, declared_earlier),
        key=lambda candidate: egglog_saturation._extraction_selection_key(
            candidate, (1, 3)
        ),
    )

    assert selected is declared_earlier


def test_typed_term_masks_constants_and_rejects_mixed_width_children():
    assert _constant(0x1FF, width=8).value == 0xFF

    with pytest.raises(ValueError, match="same width"):
        _node("add", _leaf("wide", width=32), _leaf("narrow", width=16))


def test_egglog_compatibility_reexports_the_portable_term_contract():
    assert egglog_saturation.TypedBvTerm is typed_term.TypedBvTerm
    assert egglog_saturation.canonicalize_ac_term is typed_term.canonicalize_ac_term
    assert egglog_saturation.term_cost is typed_term.term_cost
    assert egglog_saturation.term_fingerprint is typed_term.term_fingerprint


class _SameReprOpaqueKey:
    def __init__(self, identity: int):
        self.identity = identity

    def __hash__(self) -> int:
        return hash(self.identity)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _SameReprOpaqueKey) and self.identity == other.identity

    def __repr__(self) -> str:
        return "opaque-key"


class _EqualToIntOpaqueKey:
    def __hash__(self) -> int:
        return hash(1)

    def __eq__(self, other: object) -> bool:
        return type(other) is int and other == 1


def test_leaf_key_rejects_same_repr_opaque_parts_before_ac_sorting():
    first = _SameReprOpaqueKey(1)
    second = _SameReprOpaqueKey(2)
    assert first != second
    assert repr(first) == repr(second)

    for opaque in (first, second):
        with pytest.raises(ValueError, match="canonically representable"):
            TypedBvTerm(operation=None, width=32, leaf_key=(opaque,))


def test_budget_and_receipt_are_immutable_and_have_stable_contracts():
    budget = EgglogExtractionBudget()
    receipt = EgglogExtractionReceipt()

    assert budget == EgglogExtractionBudget(
        max_leaves=2,
        max_operator_nodes=10,
        max_degree=1,
        saturation_rounds=2,
        max_eclasses=64,
        max_enodes=128,
        max_rule_firings=32,
        time_budget_ms=3,
        require_proof=True,
    )
    assert receipt.selected_aliases == ()
    with pytest.raises(FrozenInstanceError):
        budget.max_degree = 2  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        receipt.degree = 1  # type: ignore[misc]


def test_budget_accepts_only_supported_semantic_degrees():
    assert EgglogExtractionBudget(max_degree=2).max_degree == 2

    for invalid in (0, 3, True):
        with pytest.raises(ValueError, match="max_degree"):
            EgglogExtractionBudget(max_degree=invalid)  # type: ignore[arg-type]


def test_extraction_skip_reason_wire_values_are_stable():
    assert {reason.name: reason.value for reason in ExtractionSkipReason} == {
        "EGGLOG_UNAVAILABLE": "egglog_unavailable",
        "UNSUPPORTED_WIDTH_SEMANTICS": "unsupported_width_semantics",
        "NON_MBA_CANDIDATE": "non_mba_candidate",
        "CANDIDATE_BUDGET": "candidate_budget",
        "TIME_BUDGET": "time_budget",
        "ECLASS_BUDGET": "eclass_budget",
        "ENODE_BUDGET": "enode_budget",
        "RULE_FIRING_BUDGET": "rule_firing_budget",
        "NO_DEGREE_ELIGIBLE_IMPROVEMENT": "no_degree_eligible_improvement",
        "LOWERING_FAILED": "lowering_failed",
        "NATIVE_Z3_FAILED": "native_z3_failed",
        "INTERNAL_ERROR": "internal_error",
        "UNAVAILABLE_EGRAPH_STATISTICS": "unavailable_egraph_statistics",
    }


@dataclass(frozen=True)
class _FakeMop:
    kind: str
    number: int
    size: int

    def to_cache_key(self) -> tuple[object, ...]:
        return (self.kind, self.number, self.size)


class _FakeAstLeaf:
    def __init__(self, name: str, mop: _FakeMop):
        self.name = name
        self.mop = mop
        self.dest_size = None

    @property
    def size(self) -> int:
        return self.mop.size

    def clone(self) -> _FakeAstLeaf:
        clone = type(self)(self.name, self.mop)
        clone.dest_size = self.dest_size
        return clone


class _FakeAstConstant(_FakeAstLeaf):
    def __init__(
        self,
        name: str,
        expected_value: int,
        expected_size: int,
    ):
        self.name = name
        self.expected_value = expected_value
        self.expected_size = expected_size
        self.mop = None
        self.dest_size = expected_size

    @property
    def size(self) -> int:
        return self.expected_size

    @property
    def value(self) -> int:
        return self.expected_value

    def clone(self) -> _FakeAstConstant:
        return type(self)(self.name, self.expected_value, self.expected_size)


class _FakeAstNode:
    def __init__(
        self,
        opcode: int,
        left: _FakeAstNode | _FakeAstLeaf,
        right: _FakeAstNode | _FakeAstLeaf | None = None,
    ):
        self.opcode = opcode
        self.left = left
        self.right = right
        self.dest_size = None
        self.size = 0


_OPCODE_BY_OPERATION = {
    "add": 1,
    "and": 2,
    "bnot": 3,
    "mul": 4,
    "neg": 5,
    "or": 6,
    "sub": 7,
    "xor": 8,
}

_MISSING_PROXY_TARGET = object()


_FakeAstProxy = type("AstProxy", (), {"__module__": __name__})


def _runtime_ast_proxy(
    target: object = _MISSING_PROXY_TARGET,
    *,
    proxy_type: type = _FakeAstProxy,
):
    proxy = object.__new__(proxy_type)
    if target is not _MISSING_PROXY_TARGET:
        object.__setattr__(proxy, "_target", target)
    return proxy


def _nested_runtime_ast_proxy(target: object, depth: int):
    for _ in range(depth):
        target = _runtime_ast_proxy(target)
    return target


@pytest.fixture
def fake_native_runtime(monkeypatch: pytest.MonkeyPatch):
    runtime = SimpleNamespace(
        AstNode=_FakeAstNode,
        AstLeaf=_FakeAstLeaf,
        AstConstant=_FakeAstConstant,
        AstProxy=_FakeAstProxy,
        operation_by_opcode={
            opcode: operation for operation, opcode in _OPCODE_BY_OPERATION.items()
        },
        opcode_by_operation=_OPCODE_BY_OPERATION,
        get_mop_key=lambda mop: mop.to_cache_key(),
    )
    monkeypatch.setattr(
        hexrays_island,
        "_load_native_runtime",
        lambda *_args: runtime,
    )
    return runtime


def test_native_lowering_preserves_live_leaf_keys_and_masks_constants(
    fake_native_runtime,
):
    leaf = _FakeAstLeaf("x", _FakeMop("register", 7, 1))
    constant = _FakeAstConstant("large", 0x1FF, 1)
    candidate = _FakeAstNode(_OPCODE_BY_OPERATION["add"], leaf, constant)
    candidate.dest_size = 1

    term = lower_native_ast_to_term(candidate, destination_size=1)

    assert term is not None
    assert term.width == 8
    assert {child.value for child in term.children if child.value is not None} == {0xFF}
    leaf_terms = [child for child in term.children if child.leaf_key is not None]
    assert len(leaf_terms) == 1
    leaf_key = leaf_terms[0].leaf_key
    assert leaf_key == ("mop", "register", 7, 1)

    rebuilt = lower_term_to_native_ast(
        term,
        leafs={leaf_key: leaf},
        destination_size=1,
    )

    assert isinstance(rebuilt, _FakeAstNode)
    assert rebuilt.dest_size == 1
    rebuilt_leafs = [
        child
        for child in (rebuilt.left, rebuilt.right)
        if isinstance(child, _FakeAstLeaf)
    ]
    assert any(
        type(child) is _FakeAstLeaf and child is not leaf for child in rebuilt_leafs
    )
    assert any(isinstance(child, _FakeAstConstant) for child in rebuilt_leafs)


@pytest.mark.parametrize("size", (1, 2, 4, 8))
def test_native_lowering_unwraps_active_runtime_proxy_and_preserves_leaf_key(
    fake_native_runtime,
    size: int,
):
    leaf = _FakeAstLeaf("x", _FakeMop("register", 7, size))
    candidate = _FakeAstNode(_OPCODE_BY_OPERATION["bnot"], leaf)
    candidate.dest_size = size
    proxy = _runtime_ast_proxy(candidate)

    term = lower_native_ast_to_term(proxy, destination_size=size)

    assert term is not None
    assert term.width == size * 8
    assert term.children[0].leaf_key == ("mop", "register", 7, size)

    leaf_key = term.children[0].leaf_key
    assert leaf_key is not None
    rebuilt = lower_term_to_native_ast(
        term,
        leafs={leaf_key: leaf},
        destination_size=size,
    )

    assert isinstance(rebuilt, _FakeAstNode)
    assert rebuilt.dest_size == size
    assert isinstance(rebuilt.left, _FakeAstLeaf)
    assert rebuilt.left is not leaf
    assert rebuilt.left.mop.to_cache_key() == ("register", 7, size)


def test_native_lowering_rejects_unknown_missing_and_cyclic_proxies(
    fake_native_runtime,
):
    leaf = _FakeAstLeaf("x", _FakeMop("register", 7, 4))
    candidate = _FakeAstNode(_OPCODE_BY_OPERATION["bnot"], leaf)
    candidate.dest_size = 4
    cyclic = _runtime_ast_proxy()
    object.__setattr__(cyclic, "_target", cyclic)

    counterfeit_proxy_type = type(
        "AstProxy",
        (),
        {"__module__": "d810.hexrays.expr.p_ast"},
    )
    proxy_subclass_type = type("AstProxySubclass", (_FakeAstProxy,), {})
    transparent_wrapper_type = type("TransparentWrapper", (), {})
    rejected = (
        _runtime_ast_proxy(candidate, proxy_type=counterfeit_proxy_type),
        _runtime_ast_proxy(candidate, proxy_type=proxy_subclass_type),
        _runtime_ast_proxy(candidate, proxy_type=transparent_wrapper_type),
        _runtime_ast_proxy(),
        cyclic,
    )

    assert all(
        lower_native_ast_to_term(proxy, destination_size=4) is None
        for proxy in rejected
    )


def test_native_lowering_requires_concrete_operator_root_after_proxy_unwrap(
    fake_native_runtime,
):
    leaf = _FakeAstLeaf("x", _FakeMop("register", 7, 4))
    constant = _FakeAstConstant("one", 1, 4)

    for root in (leaf, constant):
        assert lower_native_ast_to_term(root, destination_size=4) is None
        assert (
            lower_native_ast_to_term(
                _runtime_ast_proxy(root),
                destination_size=4,
            )
            is None
        )


def test_native_lowering_bounds_known_runtime_proxy_nesting(fake_native_runtime):
    leaf = _FakeAstLeaf("x", _FakeMop("register", 7, 4))
    candidate = _FakeAstNode(_OPCODE_BY_OPERATION["bnot"], leaf)
    candidate.dest_size = 4

    assert (
        lower_native_ast_to_term(
            _nested_runtime_ast_proxy(candidate, 3),
            destination_size=4,
        )
        is not None
    )
    assert (
        lower_native_ast_to_term(
            _nested_runtime_ast_proxy(candidate, 4),
            destination_size=4,
        )
        is None
    )


def test_native_lowering_rejects_mixed_width_and_unsupported_operations(
    fake_native_runtime,
):
    wide = _FakeAstLeaf("wide", _FakeMop("register", 1, 4))
    narrow = _FakeAstLeaf("narrow", _FakeMop("register", 2, 2))
    mixed_width_add = _FakeAstNode(_OPCODE_BY_OPERATION["add"], wide, narrow)
    mixed_width_add.dest_size = 4
    unsupported_shift = _FakeAstNode(99, wide, wide.clone())
    unsupported_shift.dest_size = 4

    assert lower_native_ast_to_term(mixed_width_add, destination_size=4) is None
    assert lower_native_ast_to_term(unsupported_shift, destination_size=4) is None


def test_native_lowering_rejects_conflicting_leaf_width_witnesses(
    fake_native_runtime,
):
    conflicting = _FakeAstLeaf("x", _FakeMop("register", 7, 4))
    conflicting.dest_size = 2
    candidate = _FakeAstNode(
        _OPCODE_BY_OPERATION["bnot"],
        conflicting,
    )
    candidate.dest_size = 4

    assert lower_native_ast_to_term(candidate, destination_size=4) is None


@pytest.mark.parametrize("missing_width", [None, 0])
def test_native_lowering_requires_operator_destination_width_witness(
    fake_native_runtime,
    missing_width: int | None,
):
    leaf = _FakeAstLeaf("x", _FakeMop("register", 7, 4))
    candidate = _FakeAstNode(_OPCODE_BY_OPERATION["bnot"], leaf)
    candidate.dest_size = missing_width

    assert lower_native_ast_to_term(candidate, destination_size=4) is None


def test_native_lowering_rejects_conflicting_operator_width_witnesses(
    fake_native_runtime,
):
    leaf = _FakeAstLeaf("x", _FakeMop("register", 7, 4))
    candidate = _FakeAstNode(_OPCODE_BY_OPERATION["bnot"], leaf)
    candidate.dest_size = 4
    candidate.size = 2

    assert lower_native_ast_to_term(candidate, destination_size=4) is None


def test_native_reconstruction_rejects_missing_leaf_and_width_mismatch(
    fake_native_runtime,
):
    leaf = _leaf("x", width=32)
    term = _node("bnot", leaf, width=32)

    assert lower_term_to_native_ast(term, leafs={}, destination_size=4) is None
    assert lower_term_to_native_ast(term, leafs={}, destination_size=2) is None


def test_native_reconstruction_rejects_leaf_mapping_identity_substitution(
    fake_native_runtime,
):
    expected_key = ("mop", "register", 7, 4)
    term = _node(
        "bnot",
        TypedBvTerm(operation=None, width=32, leaf_key=expected_key),
        width=32,
    )
    substituted = _FakeAstLeaf("other", _FakeMop("register", 8, 4))

    assert (
        lower_term_to_native_ast(
            term,
            leafs={expected_key: substituted},
            destination_size=4,
        )
        is None
    )


@pytest.mark.parametrize(
    "aliased_component",
    [_EqualToIntOpaqueKey(), True],
    ids=["custom-equal-to-int", "bool-int"],
)
def test_native_reconstruction_compares_typed_live_key_components(
    fake_native_runtime,
    aliased_component: object,
):
    expected_key = ("mop", "register", 1, 4)
    term = _node(
        "bnot",
        TypedBvTerm(operation=None, width=32, leaf_key=expected_key),
        width=32,
    )
    aliased = _FakeAstLeaf(
        "aliased",
        _FakeMop("register", aliased_component, 4),  # type: ignore[arg-type]
    )

    assert ("mop", "register", aliased_component, 4) == expected_key
    assert (
        lower_term_to_native_ast(
            term,
            leafs={expected_key: aliased},
            destination_size=4,
        )
        is None
    )


def test_extraction_result_is_immutable_and_carries_tuple_provenance():
    receipt = EgglogExtractionReceipt(
        selected_family="xor",
        selected_source="CanonicalRule",
        selected_aliases=("AliasRule",),
    )
    result = EgglogExtractionResult(
        replacement_ast=None,
        receipt=receipt,
        selected_provenance=("xor", "CanonicalRule", ("AliasRule",)),
    )

    assert result.selected_provenance == (
        "xor",
        "CanonicalRule",
        ("AliasRule",),
    )
    with pytest.raises(FrozenInstanceError):
        result.replacement_ast = object()  # type: ignore[misc]


def test_egglog_unavailability_returns_exact_noop_receipt(
    fake_native_runtime,
    monkeypatch: pytest.MonkeyPatch,
):
    candidate = _FakeAstNode(
        _OPCODE_BY_OPERATION["add"],
        _FakeAstLeaf("x", _FakeMop("register", 1, 4)),
        _FakeAstLeaf("y", _FakeMop("register", 2, 4)),
    )
    candidate.dest_size = 4
    monkeypatch.setattr(egglog_saturation, "_load_egglog_module", lambda: None)

    result = extract_bounded_candidate(
        candidate,
        (),
        EgglogExtractionBudget(time_budget_ms=1000),
        4,
    )

    assert result.replacement_ast is None
    assert result.receipt.skip_reason is ExtractionSkipReason.EGGLOG_UNAVAILABLE
    assert result.receipt.island_class == "not_mba"
    assert result.receipt.island_fingerprint is not None
    assert result.receipt.operator_count == 1
    assert result.receipt.distinct_leaf_count == 2
    assert result.receipt.blockers == ()
    assert result.selected_provenance is None


def test_operator_budget_returns_candidate_budget_before_registration(
    fake_native_runtime,
    monkeypatch: pytest.MonkeyPatch,
):
    candidate = _FakeAstNode(
        _OPCODE_BY_OPERATION["add"],
        _FakeAstLeaf("x", _FakeMop("register", 1, 4)),
        _FakeAstNode(
            _OPCODE_BY_OPERATION["xor"],
            _FakeAstLeaf("x", _FakeMop("register", 1, 4)),
            _FakeAstLeaf("y", _FakeMop("register", 2, 4)),
        ),
    )
    candidate.dest_size = 4
    candidate.right.dest_size = 4

    class _FreshEGraph:
        instances = 0

        def __init__(self):
            type(self).instances += 1

        def register(self, *_commands):
            raise AssertionError("candidate cap must precede registration")

    monkeypatch.setattr(
        egglog_saturation,
        "_load_egglog_module",
        lambda: SimpleNamespace(EGraph=_FreshEGraph),
    )

    result = extract_bounded_candidate(
        candidate,
        (),
        EgglogExtractionBudget(max_operator_nodes=1),
        4,
    )

    assert _FreshEGraph.instances == 0
    assert result.receipt.input_cost == (2, 5)
    assert result.receipt.island_class == "linear_mba"
    assert result.receipt.operator_count == 2
    assert result.receipt.skip_reason is ExtractionSkipReason.CANDIDATE_BUDGET


def test_injected_monotonic_clock_returns_time_budget_noop(
    fake_native_runtime,
    monkeypatch: pytest.MonkeyPatch,
):
    candidate = _FakeAstNode(
        _OPCODE_BY_OPERATION["add"],
        _FakeAstLeaf("x", _FakeMop("register", 1, 4)),
        _FakeAstLeaf("y", _FakeMop("register", 2, 4)),
    )
    candidate.dest_size = 4
    ticks = iter((10.0, 10.004, 10.004))

    class _FreshEGraph:
        def register(self, *_commands):
            raise AssertionError("time cap must precede registration")

    monkeypatch.setattr(
        egglog_saturation,
        "_load_egglog_module",
        lambda: SimpleNamespace(EGraph=_FreshEGraph),
    )
    monkeypatch.setattr(egglog_saturation, "_monotonic", lambda: next(ticks))

    result = extract_bounded_candidate(
        candidate,
        (),
        EgglogExtractionBudget(time_budget_ms=3),
        4,
    )

    assert result.replacement_ast is None
    assert result.receipt.elapsed_ms == pytest.approx(4.0)
    assert result.receipt.skip_reason is ExtractionSkipReason.TIME_BUDGET


def test_default_time_budget_does_not_load_or_construct_egglog(
    fake_native_runtime,
    monkeypatch: pytest.MonkeyPatch,
):
    candidate = _FakeAstNode(
        _OPCODE_BY_OPERATION["add"],
        _FakeAstLeaf("x", _FakeMop("register", 1, 4)),
        _FakeAstLeaf("y", _FakeMop("register", 2, 4)),
    )
    candidate.dest_size = 4

    def unavailable_egglog() -> None:
        raise AssertionError("the 3 ms telemetry/no-op path must not load Egglog")

    monkeypatch.setattr(egglog_saturation, "_load_egglog_module", unavailable_egglog)

    result = extract_bounded_candidate(
        candidate,
        (),
        EgglogExtractionBudget(),
        4,
    )

    assert result.replacement_ast is None
    assert result.receipt.input_cost == (1, 3)
    assert result.receipt.skip_reason is ExtractionSkipReason.TIME_BUDGET


def test_distinct_live_leaf_cap_returns_candidate_budget(
    fake_native_runtime,
    monkeypatch: pytest.MonkeyPatch,
):
    candidate = _FakeAstNode(
        _OPCODE_BY_OPERATION["add"],
        _FakeAstLeaf("x", _FakeMop("register", 1, 4)),
        _FakeAstLeaf("y", _FakeMop("register", 2, 4)),
    )
    candidate.dest_size = 4

    class _FreshEGraph:
        def register(self, *_commands):
            raise AssertionError("leaf cap must precede registration")

    monkeypatch.setattr(
        egglog_saturation,
        "_load_egglog_module",
        lambda: SimpleNamespace(EGraph=_FreshEGraph),
    )

    result = extract_bounded_candidate(
        candidate,
        (),
        EgglogExtractionBudget(max_leaves=1),
        4,
    )

    assert result.receipt.input_cost == (1, 3)
    assert result.receipt.skip_reason is ExtractionSkipReason.CANDIDATE_BUDGET


@pytest.mark.parametrize("malformation", ["missing", "truncated", "unknown"])
def test_private_egraph_statistics_shape_drift_fails_closed(malformation: str):
    class _Serialized:
        truncated_functions = []
        discarded_functions = []

        def to_json(self):
            if malformation == "unknown":
                return '{"nodes": [], "class_data": {}}'
            return '{"nodes": {}, "class_data": {}, "root_eclasses": []}'

    class _EGraph:
        if malformation != "missing":

            def _serialize(self):
                serialized = _Serialized()
                if malformation == "truncated":
                    serialized.truncated_functions = ["BvExpr.binary"]
                return serialized

    assert (
        egglog_statistics.read_egraph_statistics(_EGraph(), egglog_version="13.2.0")
        is None
    )


def test_private_statistics_boundary_rejects_unpinned_egglog_version():
    class _EGraph:
        def _serialize(self):
            raise AssertionError("unsupported versions must fail before serialization")

    assert (
        egglog_statistics.read_egraph_statistics(_EGraph(), egglog_version="13.2.1")
        is None
    )


def test_run_report_match_counts_are_never_guessed():
    assert (
        egglog_statistics.read_rule_firing_count(
            SimpleNamespace(num_matches_per_rule={"r0": 2, "r1": 3})
        )
        == 5
    )
    assert (
        egglog_statistics.read_rule_firing_count(
            SimpleNamespace(num_matches_per_rule={"r0": True})
        )
        is None
    )
    assert egglog_statistics.read_rule_firing_count(SimpleNamespace()) is None


@pytest.fixture(scope="module")
def admitted_xor_nested_stuff():
    catalogue = _compile_rule_families({"xor": (Xor_NestedStuff,)})
    assert len(catalogue.compiled_rules) == 1
    return catalogue.compiled_rules[0]


def test_actual_xor_nested_stuff_canonical_pattern_backtracks_ac_bindings(
    admitted_xor_nested_stuff,
):
    canonical = admitted_xor_nested_stuff
    candidate = _term_from_symbolic(canonical.pattern)

    replacement = apply_compiled_rule_to_term(canonical, candidate)

    assert replacement == _term_from_symbolic(canonical.replacement)


def test_real_canonical_compiled_rule_instance_is_admitted(
    admitted_xor_nested_stuff,
):
    canonical = admitted_xor_nested_stuff
    candidate = _term_from_symbolic(canonical.pattern)

    assert apply_compiled_rule_to_term(canonical, candidate) is not None


def test_replaced_canonical_compiled_rule_instance_is_not_admitted(
    admitted_xor_nested_stuff,
):
    canonical = admitted_xor_nested_stuff
    copied = replace(canonical)
    candidate = _term_from_symbolic(canonical.pattern)

    assert copied is not canonical
    assert apply_compiled_rule_to_term(copied, candidate) is None


def test_fabricated_skip_verification_compiled_rule_is_not_admitted():
    class _FabricatedUnverifiedRule(VerifiableRule):
        SKIP_VERIFICATION = True
        PATTERN = Xor_NestedStuff.x9 ^ Xor_NestedStuff.x10
        REPLACEMENT = Xor_NestedStuff.x9

    fabricated = CompiledEgglogRule(
        family="xor",
        source_name="FabricatedUnverifiedRule",
        aliases=(),
        rule_type=_FabricatedUnverifiedRule,
        proof_widths=CERTIFICATE_WIDTHS,
        guarded=False,
    )
    candidate = _term_from_symbolic(fabricated.pattern)

    assert apply_compiled_rule_to_term(fabricated, candidate) is None


def test_copied_self_authentication_fields_do_not_admit_fabricated_rule(
    admitted_xor_nested_stuff,
):
    class _FabricatedUnverifiedRule(VerifiableRule):
        SKIP_VERIFICATION = True
        PATTERN = Xor_NestedStuff.x9 ^ Xor_NestedStuff.x10
        REPLACEMENT = Xor_NestedStuff.x9

    canonical = admitted_xor_nested_stuff
    copied_credentials = {
        item.name: getattr(canonical, item.name)
        for item in fields(canonical)
        if item.name.startswith("_admission_")
    }
    fabricated = CompiledEgglogRule(
        family="xor",
        source_name="FabricatedUnverifiedRule",
        aliases=(),
        rule_type=_FabricatedUnverifiedRule,
        proof_widths=CERTIFICATE_WIDTHS,
        guarded=False,
        **copied_credentials,
    )
    if hasattr(
        egglog_add_rule_compiler,
        "_compiled_rule_admission_signature",
    ):
        fabricated = replace(
            fabricated,
            _admission_signature=(
                egglog_add_rule_compiler._compiled_rule_admission_signature(fabricated)
            ),
        )
    candidate = _term_from_symbolic(fabricated.pattern)

    assert apply_compiled_rule_to_term(fabricated, candidate) is None


def test_admitted_compiled_rule_rejects_tampered_catalogue_metadata(
    admitted_xor_nested_stuff,
):
    canonical = admitted_xor_nested_stuff
    candidate = _term_from_symbolic(canonical.pattern)
    tampered_fields = {
        "family": "add",
        "source_name": "FabricatedCanonicalName",
        "aliases": ("FabricatedAlias",),
        "rule_type": VerifiableRule,
        "proof_widths": (32,),
        "guarded": True,
    }

    for field, replacement in tampered_fields.items():
        tampered = replace(canonical, **{field: replacement})
        assert apply_compiled_rule_to_term(tampered, candidate) is None


@pytest.mark.parametrize("malformation", ["run-report", "serialization"])
def test_unknown_runtime_statistics_return_exact_unavailable_receipt(
    fake_native_runtime,
    monkeypatch: pytest.MonkeyPatch,
    malformation: str,
):
    candidate = _FakeAstNode(
        _OPCODE_BY_OPERATION["add"],
        _FakeAstLeaf("x", _FakeMop("register", 1, 4)),
        _FakeAstLeaf("y", _FakeMop("register", 2, 4)),
    )
    candidate.dest_size = 4

    class _Serialized:
        truncated_functions = []
        discarded_functions = []

        @staticmethod
        def to_json():
            if malformation == "serialization":
                return '{"nodes": [], "class_data": {}}'
            return '{"nodes": {}, "class_data": {}, "root_eclasses": []}'

    class _FreshEGraph:
        def register(self, *_commands):
            return None

        def run(self, _rounds):
            if malformation == "run-report":
                return SimpleNamespace()
            return SimpleNamespace(num_matches_per_rule={"canonical-rule": 2})

        def _serialize(self):
            return _Serialized()

    monkeypatch.setattr(
        egglog_saturation,
        "_load_egglog_module",
        lambda: SimpleNamespace(EGraph=_FreshEGraph),
    )

    result = extract_bounded_candidate(
        candidate,
        (),
        EgglogExtractionBudget(time_budget_ms=1000),
        4,
    )

    assert result.replacement_ast is None
    assert (
        result.receipt.skip_reason is ExtractionSkipReason.UNAVAILABLE_EGRAPH_STATISTICS
    )
    assert result.receipt.rule_firings == (0 if malformation == "run-report" else 2)


def test_frontier_time_exhaustion_stops_before_run(
    fake_native_runtime,
    monkeypatch: pytest.MonkeyPatch,
):
    candidate = _FakeAstNode(
        _OPCODE_BY_OPERATION["add"],
        _FakeAstLeaf("x", _FakeMop("register", 1, 4)),
        _FakeAstLeaf("y", _FakeMop("register", 2, 4)),
    )
    candidate.dest_size = 4
    ticks = iter((10.0, 10.0, 10.0, 11.004, 11.004))
    applications: list[object] = []

    class _FreshEGraph:
        def register(self, *_commands):
            raise AssertionError("expired frontier must not be registered")

        def run(self, _rounds):
            raise AssertionError("expired frontier must not run")

    rule = SimpleNamespace(
        family="xor", source_name="Rule", aliases=(), pattern=object()
    )
    monkeypatch.setattr(
        egglog_saturation,
        "_load_egglog_module",
        lambda: SimpleNamespace(EGraph=_FreshEGraph),
    )
    monkeypatch.setattr(egglog_saturation, "_monotonic", lambda: next(ticks))
    monkeypatch.setattr(
        egglog_add_rule_compiler,
        "executable_rule_order_key",
        lambda _rule: (),
    )
    monkeypatch.setattr(
        egglog_add_rule_compiler,
        "apply_compiled_rule_to_term",
        lambda _rule, term: applications.append(term) or term,
    )

    result = extract_bounded_candidate(
        candidate,
        (rule, rule),
        EgglogExtractionBudget(time_budget_ms=1000),
        4,
    )

    assert len(applications) == 1
    assert result.receipt.skip_reason is ExtractionSkipReason.TIME_BUDGET


def test_pre_run_frontier_firing_cap_avoids_registration_and_execution(
    fake_native_runtime,
    monkeypatch: pytest.MonkeyPatch,
):
    candidate = _FakeAstNode(
        _OPCODE_BY_OPERATION["add"],
        _FakeAstLeaf("x", _FakeMop("register", 1, 4)),
        _FakeAstLeaf("y", _FakeMop("register", 2, 4)),
    )
    candidate.dest_size = 4

    class _FreshEGraph:
        def register(self, *_commands):
            raise AssertionError("over-budget frontier must not be registered")

        def run(self, _rounds):
            raise AssertionError("over-budget frontier must not run")

    rules = tuple(
        SimpleNamespace(family="xor", source_name=name, aliases=(), pattern=object())
        for name in ("RuleA", "RuleB")
    )
    monkeypatch.setattr(
        egglog_saturation,
        "_load_egglog_module",
        lambda: SimpleNamespace(EGraph=_FreshEGraph),
    )
    monkeypatch.setattr(
        egglog_add_rule_compiler,
        "executable_rule_order_key",
        lambda rule: rule.source_name,
    )
    monkeypatch.setattr(
        egglog_add_rule_compiler,
        "apply_compiled_rule_to_term",
        lambda _rule, term: term,
    )
    monkeypatch.setattr(
        egglog_saturation,
        "DegreeExpr",
        SimpleNamespace(at=lambda degree, expression: (degree, expression)),
    )
    monkeypatch.setattr(egglog_saturation, "_term_to_egglog", lambda term: term)
    monkeypatch.setattr(
        egglog_saturation,
        "_load_egglog_module",
        lambda: SimpleNamespace(
            EGraph=_FreshEGraph,
            rewrite=lambda source: SimpleNamespace(
                to=lambda target: SimpleNamespace(
                    decl=(source, target),
                )
            ),
        ),
    )

    result = extract_bounded_candidate(
        candidate,
        rules,
        EgglogExtractionBudget(max_rule_firings=1, time_budget_ms=1000),
        4,
    )

    assert result.receipt.skip_reason is ExtractionSkipReason.RULE_FIRING_BUDGET


def test_default_three_ms_guard_rejects_estimated_run_before_egglog_execution(
    fake_native_runtime,
    monkeypatch: pytest.MonkeyPatch,
):
    candidate = _FakeAstNode(
        _OPCODE_BY_OPERATION["add"],
        _FakeAstLeaf("x", _FakeMop("register", 1, 4)),
        _FakeAstLeaf("y", _FakeMop("register", 2, 4)),
    )
    candidate.dest_size = 4
    calls: list[str] = []

    class _FreshEGraph:
        def register(self, *_commands):
            calls.append("register")

        def run(self, _rounds):
            calls.append("run")
            raise AssertionError("pre-run estimate must reject this workload")

    rule = SimpleNamespace(family="xor", source_name="Rule", aliases=())
    monkeypatch.setattr(
        egglog_saturation,
        "DegreeExpr",
        SimpleNamespace(at=lambda degree, expression: (degree, expression)),
    )
    monkeypatch.setattr(egglog_saturation, "_term_to_egglog", lambda term: term)
    monkeypatch.setattr(
        egglog_saturation,
        "_load_egglog_module",
        lambda: SimpleNamespace(
            EGraph=_FreshEGraph,
            rewrite=lambda source: SimpleNamespace(
                to=lambda target: SimpleNamespace(decl=(source, target))
            ),
        ),
    )
    monkeypatch.setattr(
        egglog_add_rule_compiler,
        "apply_compiled_rule_to_term",
        lambda _rule, term: term,
    )

    result = extract_bounded_candidate(candidate, (rule,), EgglogExtractionBudget(), 4)

    assert calls == []
    assert result.receipt.skip_reason is ExtractionSkipReason.TIME_BUDGET


def test_exploration_contract_is_candidate_root_only(
    fake_native_runtime,
    monkeypatch: pytest.MonkeyPatch,
):
    candidate = _FakeAstNode(
        _OPCODE_BY_OPERATION["add"],
        _FakeAstNode(
            _OPCODE_BY_OPERATION["xor"],
            _FakeAstLeaf("x", _FakeMop("register", 1, 4)),
            _FakeAstLeaf("y", _FakeMop("register", 2, 4)),
        ),
        _FakeAstLeaf("z", _FakeMop("register", 3, 4)),
    )
    candidate.dest_size = 4
    candidate.left.dest_size = 4
    visited: list[TypedBvTerm] = []

    class _FreshEGraph:
        def register(self, *_commands):
            return None

        def run(self, _rounds):
            return SimpleNamespace(num_matches_per_rule={})

    rule = SimpleNamespace(family="xor", source_name="Rule", aliases=())
    monkeypatch.setattr(
        egglog_saturation,
        "_load_egglog_module",
        lambda: SimpleNamespace(EGraph=_FreshEGraph),
    )
    monkeypatch.setattr(
        egglog_add_rule_compiler,
        "executable_rule_order_key",
        lambda _rule: (),
    )
    monkeypatch.setattr(
        egglog_add_rule_compiler,
        "apply_compiled_rule_to_term",
        lambda _rule, term: visited.append(term) or None,
    )

    extract_bounded_candidate(
        candidate,
        (rule,),
        EgglogExtractionBudget(max_leaves=3, time_budget_ms=1000),
        4,
    )

    assert egglog_saturation.EGGLOG_EXPLORATION_SCOPE == "candidate-root-only"
    assert len(visited) == 1
    assert visited[0].operation == "add"
