"""Tests for the portable root-chain capability consumed by provider routing."""

from __future__ import annotations

from d810.mba.island_profile import profile_typed_term
from d810.mba.provider_routing import MbaProviderKind, provider_route
from d810.mba.root_chain_descriptor import (
    MbaRootChainFamily,
    describe_root_chain,
)
from d810.mba.typed_term import TypedBvTerm


def _leaf(name: str) -> TypedBvTerm:
    return TypedBvTerm(operation=None, width=32, leaf_key=("register", name))


def _node(
    operation: str,
    left: TypedBvTerm,
    right: TypedBvTerm | None = None,
) -> TypedBvTerm:
    children = (left,) if right is None else (left, right)
    return TypedBvTerm(operation=operation, width=32, children=children)


def test_same_opcode_chain_descriptor_allows_complement_operands() -> None:
    term = _node("and", _leaf("a"), _node("bnot", _leaf("a")))

    descriptor = describe_root_chain(term)

    assert descriptor is not None
    assert descriptor.family is MbaRootChainFamily.SAME_OPERATION
    assert descriptor.root_operation == "and"
    assert descriptor.flattened_arity == 2
    assert descriptor.fingerprint == profile_typed_term(term).fingerprint
    assert provider_route(
        profile_typed_term(term),
        chain_descriptor=descriptor,
    ) == (MbaProviderKind.STRUCTURAL_CHAIN, MbaProviderKind.CATALOGUE)


def test_arithmetic_chain_descriptor_flattens_add_and_sub_as_one_signed_chain() -> None:
    term = _node(
        "add",
        _leaf("a"),
        _node("sub", _leaf("b"), _leaf("b")),
    )

    descriptor = describe_root_chain(term)

    assert descriptor is not None
    assert descriptor.family is MbaRootChainFamily.ARITHMETIC_ADDITIVE
    assert descriptor.root_operation == "add"
    assert descriptor.flattened_arity == 3
    assert provider_route(
        profile_typed_term(term),
        chain_descriptor=descriptor,
    ) == (MbaProviderKind.STRUCTURAL_CHAIN, MbaProviderKind.CATALOGUE)


def test_arithmetic_chain_descriptor_flattens_nested_neg_operands() -> None:
    term = _node("sub", _leaf("a"), _node("neg", _leaf("b")))

    descriptor = describe_root_chain(term)

    assert descriptor is not None
    assert descriptor.family is MbaRootChainFamily.ARITHMETIC_ADDITIVE
    assert descriptor.root_operation == "sub"
    assert descriptor.flattened_arity == 2


def test_non_chain_root_is_not_described_even_if_its_child_is_a_chain() -> None:
    term = _node("bnot", _node("and", _leaf("a"), _leaf("b")))

    assert describe_root_chain(term) is None
