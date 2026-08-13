from __future__ import annotations

from dataclasses import FrozenInstanceError, dataclass
from types import SimpleNamespace

import pytest

from d810.backends.mba import egglog_saturation
from d810.backends.mba.egglog_saturation import (
    EgglogExtractionBudget,
    EgglogExtractionReceipt,
    ExtractionSkipReason,
    TypedBvTerm,
    canonicalize_ac_term,
    lower_native_ast_to_term,
    lower_term_to_native_ast,
)


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


def test_typed_term_masks_constants_and_rejects_mixed_width_children():
    assert _constant(0x1FF, width=8).value == 0xFF

    with pytest.raises(ValueError, match="same width"):
        _node("add", _leaf("wide", width=32), _leaf("narrow", width=16))


class _SameReprOpaqueKey:
    def __init__(self, identity: int):
        self.identity = identity

    def __hash__(self) -> int:
        return hash(self.identity)

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, _SameReprOpaqueKey)
            and self.identity == other.identity
        )

    def __repr__(self) -> str:
        return "opaque-key"


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


@pytest.fixture
def fake_native_runtime(monkeypatch: pytest.MonkeyPatch):
    runtime = SimpleNamespace(
        AstNode=_FakeAstNode,
        AstLeaf=_FakeAstLeaf,
        AstConstant=_FakeAstConstant,
        operation_by_opcode={
            opcode: operation for operation, opcode in _OPCODE_BY_OPERATION.items()
        },
        opcode_by_operation=_OPCODE_BY_OPERATION,
        get_mop_key=lambda mop: mop.to_cache_key(),
    )
    monkeypatch.setattr(egglog_saturation, "_load_native_runtime", lambda: runtime)
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
    assert {child.value for child in term.children if child.value is not None} == {
        0xFF
    }
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
        child for child in (rebuilt.left, rebuilt.right) if isinstance(child, _FakeAstLeaf)
    ]
    assert any(type(child) is _FakeAstLeaf and child is not leaf for child in rebuilt_leafs)
    assert any(isinstance(child, _FakeAstConstant) for child in rebuilt_leafs)


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
    assert (
        lower_term_to_native_ast(term, leafs={}, destination_size=2) is None
    )


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
