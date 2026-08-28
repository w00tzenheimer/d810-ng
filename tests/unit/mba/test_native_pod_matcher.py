"""Packed native MBA matcher contracts independent of Hex-Rays runtime."""

from __future__ import annotations

from dataclasses import replace

import pytest

from d810.backends.mba import native_pod_matcher
from d810.backends.mba.compiled_pattern_catalogue import CompiledPatternCatalogue
from d810.mba.certified_rule_compiler import (
    _compile_rule_families,
    compile_add_rule_catalogue,
)
from d810.backends.mba.native_mba_term_view import NativeMbaTermView
from d810.backends.mba.native_pod_matcher import (
    OP_ADD,
    PackedNativeMbaTerm,
    match_root_pod,
)
from d810.mba.rules.sub import Sub_HackersDelightRule_2
from d810.mba.rules.eid import (
    Add_EidSboxOffset13_1,
    Add_EidSboxOffset23_1,
    Bnot_EidSboxOffset27_1,
    Or_EidRepeatedMaskedOperand_1,
    Xor_EidComplementConsensus_1,
    Xor_EidComplementPartition_1,
    Xor_EidComplementPartition_2,
    Xor_EidComplementPartition_3,
)
from d810.mba.typed_term import term_fingerprint
from d810.mba.dsl import Const, Var
from d810.mba.rules._base import VerifiableRule
from d810.mba.certified_catalogue import (
    CertifiedCatalogueSnapshot,
    StructuralMatcherParityCertificate,
    StructuralMatcherParityExpectation,
)


_TIGHT_X, _TIGHT_Y, _TIGHT_Z = Var("tight_x"), Var("tight_y"), Var("tight_z")
_TIGHT_ZERO = Const("tight_zero", 0)


class _ImpossibleBeforeValidRule(VerifiableRule):
    """A valid schema that cannot fit into the three-node test candidate."""

    PATTERN = _TIGHT_X + (_TIGHT_Y & _TIGHT_Z)
    REPLACEMENT = PATTERN


class _ValidAfterImpossibleRule(VerifiableRule):
    """A later valid zero-addition simplification."""

    PATTERN = _TIGHT_X + _TIGHT_ZERO
    REPLACEMENT = _TIGHT_X


def _leaf(name: str, *, width: int = 32) -> NativeMbaTermView:
    return NativeMbaTermView(
        None,
        width,
        leaf_key=("mop", "r", name),
        native_operand=object(),
    )


def _constant(value: int, *, width: int = 32) -> NativeMbaTermView:
    return NativeMbaTermView(None, width, constant_value=value)


def _node(
    name: str, *children: NativeMbaTermView, width: int = 32
) -> NativeMbaTermView:
    return NativeMbaTermView(name, width, children=children)


def _runtime_authorization_case(digest: str):
    snapshot = CertifiedCatalogueSnapshot(
        fingerprint="a" * 64,
        rules_in_declaration_order=(),
        rule_ids_by_root_shape={},
        structural_authorizable=True,
        runtime_semantics_digest=digest,
    )
    expectation = StructuralMatcherParityExpectation(
        corpus_digest="b" * 64,
        toolchain_digest="c" * 64,
        runtime_semantics_digest=digest,
        legacy_observation_count=1,
        observation_count=1,
    )
    certificate = StructuralMatcherParityCertificate(
        snapshot_fingerprint=snapshot.fingerprint,
        runtime_mode="python",
        corpus_digest=expectation.corpus_digest,
        toolchain_digest=expectation.toolchain_digest,
        runtime_semantics_digest=digest,
        legacy_observation_count=1,
        observation_count=1,
        legacy_rule_mismatches=0,
        legacy_binding_mismatches=0,
        legacy_binding_unknown=0,
        new_safe_coverage_pending=0,
        unsafe_mutations=0,
        unproved_structural_replacements=0,
    )
    return snapshot, expectation, certificate


def test_runtime_digest_binds_active_pod_backend_and_artifact_identity() -> None:
    identity = native_pod_matcher.active_runtime_identity()
    digest = native_pod_matcher.runtime_semantics_digest(identity=identity)

    backend_changed = replace(
        identity,
        pod_backend="cython" if identity.pod_backend == "python" else "python",
    )
    artifact_changed = replace(
        identity,
        artifact_identity=f"{identity.artifact_identity}:changed",
    )
    assert native_pod_matcher.runtime_semantics_digest(identity=backend_changed) != digest
    changed_digest = native_pod_matcher.runtime_semantics_digest(
        identity=artifact_changed
    )
    assert changed_digest != digest

    snapshot, expectation, certificate = _runtime_authorization_case(digest)
    assert certificate.authorizes(snapshot, "python", expectation) is True
    stale_snapshot = replace(snapshot, runtime_semantics_digest=changed_digest)
    assert certificate.authorizes(stale_snapshot, "python", expectation) is False


def _rule(name: str):
    return compile_add_rule_catalogue().receipt_for(name).compiled_rule


def test_packed_view_separates_numeric_nodes_from_live_identity_sidecar() -> None:
    x, y = _leaf("x"), _leaf("y")
    packed = PackedNativeMbaTerm.from_view(_node("add", x, y))
    root = packed.nodes[packed.root_index]

    assert root.operation == OP_ADD
    assert all(type(node.literal_u64) is int for node in packed.nodes)
    assert packed.sidecar[root.left_index] is x
    assert packed.sidecar[root.right_index] is y


def test_packed_view_retains_associative_binary_structure_for_numeric_matching() -> (
    None
):
    x, y, z = _leaf("x"), _leaf("y"), _leaf("z")
    packed = PackedNativeMbaTerm.from_view(_node("add", _node("add", x, y), z))
    root = packed.nodes[packed.root_index]

    assert root.operation == OP_ADD
    assert packed.nodes[root.left_index].operation == OP_ADD
    assert len(packed.nodes) == 5


def test_packed_view_materializes_one_shared_portable_term() -> None:
    x, y = _leaf("x"), _leaf("y")
    candidate = _node("add", _node("xor", x, y), _constant(1))
    packed = PackedNativeMbaTerm.from_view(candidate)

    first = packed.typed_term()

    assert first == candidate.to_typed_term()
    assert packed.typed_term() is first
    assert packed.typed_term(packed.root_index) is first


def test_packed_view_uses_ac_identity_for_repeated_operand_checks(monkeypatch) -> None:
    a, b = _leaf("a"), _leaf("b")
    shared = _node("add", a, b)
    packed = PackedNativeMbaTerm.from_view(_node("xor", shared, shared))
    root = packed.nodes[packed.root_index]
    calls = 0
    original = NativeMbaTermView.canonical_children

    def observed(view: NativeMbaTermView):
        nonlocal calls
        calls += 1
        return original(view)

    monkeypatch.setattr(NativeMbaTermView, "canonical_children", observed)
    rows = packed.numeric_rows()

    assert rows[root.left_index][7] == rows[root.right_index][7]
    assert calls == 0


def test_pod_adapter_matches_portable_catalogue_exactly() -> None:
    rule = _rule("Add_HackersDelightRule_2")
    assert rule is not None
    catalogue = CompiledPatternCatalogue.from_rules((rule,))
    x, y = _leaf("x"), _leaf("y")
    candidate = _node(
        "add",
        _node("xor", y, x),
        _node("mul", _constant(2), _node("and", y, x)),
    )

    assert match_root_pod(catalogue, candidate, comparison_budget=64) == (
        catalogue.match_root(candidate, comparison_budget=64)
    )


def test_pod_adapter_preserves_asymmetric_subtraction_bindings() -> None:
    """AC traversal must retain the binding orientation used by ``x - y``."""

    rules = _compile_rule_families({"sub": (Sub_HackersDelightRule_2,)}).compiled_rules
    catalogue = CompiledPatternCatalogue.from_rules(rules)
    a, b = _leaf("a"), _leaf("b")
    candidate = _node(
        "sub",
        _node("xor", a, b),
        _node("mul", _constant(2), _node("and", a, _node("bnot", b))),
    )

    def replacement_fingerprints(result):
        return tuple(
            term_fingerprint(match.bindings.materialize_replacement(match.rule))
            for match in result.matches
        )

    portable = catalogue._match_root_portable(candidate, comparison_budget=64)
    pod = match_root_pod(catalogue, candidate, comparison_budget=64)

    assert replacement_fingerprints(pod) == replacement_fingerprints(portable)


def test_eid_or_rule_binds_one_repeated_compound_operand() -> None:
    rules = _compile_rule_families(
        {"or": (Or_EidRepeatedMaskedOperand_1,)}
    ).compiled_rules
    catalogue = CompiledPatternCatalogue.from_rules(rules)
    x = _leaf("x")
    masked_source = _leaf("masked_source")

    def masked_operand() -> NativeMbaTermView:
        return _node("and", masked_source, _constant(0xFFFFFBFB))

    candidate = _node(
        "add",
        _node(
            "sub",
            _node("xor", x, masked_operand()),
            _node(
                "add",
                _node("and", x, masked_operand()),
                _node(
                    "mul",
                    _constant(2),
                    _node("and", masked_operand(), _node("bnot", x)),
                ),
            ),
        ),
        _node("mul", _constant(2), masked_operand()),
    )

    portable = catalogue._match_root_portable(candidate, comparison_budget=512)
    pod = match_root_pod(catalogue, candidate, comparison_budget=512)

    assert tuple(match.rule.source_name for match in portable.matches) == (
        "Or_EidRepeatedMaskedOperand_1",
    )
    assert pod == portable


def _assert_exact_eid_xor_candidate_matches(
    rule_type: type[VerifiableRule], candidate: NativeMbaTermView
) -> None:
    rules = _compile_rule_families({"xor": (rule_type,)}).compiled_rules
    catalogue = CompiledPatternCatalogue.from_rules(rules)

    portable = catalogue._match_root_portable(candidate, comparison_budget=1024)
    pod = match_root_pod(catalogue, candidate, comparison_budget=1024)

    assert tuple(match.rule.source_name for match in portable.matches) == (
        rule_type.__name__,
    )
    assert pod == portable


def _assert_exact_eid_candidate_matches(
    family: str,
    rule_type: type[VerifiableRule],
    candidate: NativeMbaTermView,
) -> None:
    rules = _compile_rule_families({family: (rule_type,)}).compiled_rules
    catalogue = CompiledPatternCatalogue.from_rules(rules)

    portable = catalogue._match_root_portable(candidate, comparison_budget=4096)
    pod = match_root_pod(catalogue, candidate, comparison_budget=4096)

    assert tuple(match.rule.source_name for match in portable.matches) == (
        rule_type.__name__,
    )
    assert pod == portable


@pytest.mark.parametrize(
    ("rule_type", "offset", "low_clear", "clear", "bias"),
    (
        (
            Add_EidSboxOffset13_1,
            0x13,
            0x7FFFFFFFFFFFFFEC,
            0xFFFFFFFFFFFFFFEC,
            0x49,
        ),
        (
            Add_EidSboxOffset23_1,
            0x23,
            0x7FFFFFFFFFFFFFDC,
            0xFFFFFFFFFFFFFFDC,
            0x89,
        ),
    ),
)
def test_eid_sbox_offset_rules_match_exact_64_bit_source_trees(
    rule_type: type[VerifiableRule],
    offset: int,
    low_clear: int,
    clear: int,
    bias: int,
) -> None:
    width = 64
    value = _leaf("value", width=width)

    def c(number: int) -> NativeMbaTermView:
        return _constant(number, width=width)

    def binary(name: str, left, right) -> NativeMbaTermView:
        return _node(name, left, right, width=width)

    candidate = binary(
        "sub",
        binary(
            "sub",
            binary(
                "add",
                binary(
                    "sub",
                    binary(
                        "add",
                        binary(
                            "sub",
                            binary("mul", c(2), binary("and", value, c(offset))),
                            binary("mul", c(6), binary("and", value, c(low_clear))),
                        ),
                        binary("mul", c(11), binary("and", value, c(clear))),
                    ),
                    binary("mul", c(7), value),
                ),
                c(bias),
            ),
            binary("mul", c(3), binary("and", _node("bnot", value, width=width), c(offset))),
        ),
        binary("mul", c(3), _node("bnot", value, width=width)),
    )

    _assert_exact_eid_candidate_matches("add", rule_type, candidate)


def test_eid_sbox_offset_27_rule_matches_exact_64_bit_source_tree() -> None:
    width = 64
    value = _leaf("value", width=width)

    def c(number: int) -> NativeMbaTermView:
        return _constant(number, width=width)

    def binary(name: str, left, right) -> NativeMbaTermView:
        return _node(name, left, right, width=width)

    not_value = _node("bnot", value, width=width)
    inner = binary(
        "sub",
        binary(
            "sub",
            binary(
                "sub",
                binary("sub", binary("or", not_value, c(0x27)), c(3)),
                binary(
                    "add",
                    binary("mul", c(2), binary("and", value, c(0x7FFFFFFFFFFFFFD8))),
                    binary("mul", c(2), binary("and", value, c(0x27))),
                ),
            ),
            binary("mul", c(4), binary("and", not_value, c(0x3FFFFFFFFFFFFFD8))),
        ),
        binary("mul", c(3), binary("and", not_value, c(0x27))),
    )
    candidate = _node("bnot", inner, width=width)

    _assert_exact_eid_candidate_matches("bnot", Bnot_EidSboxOffset27_1, candidate)


def test_eid_complement_consensus_matches_exact_64_bit_source_tree() -> None:
    width = 64
    value = _leaf("value", width=width)
    mask = _leaf("mask", width=width)
    candidate = _node(
        "sub",
        _node(
            "sub",
            _node(
                "mul",
                _constant(2, width=width),
                _node("bnot", _node("and", value, mask, width=width), width=width),
                width=width,
            ),
            _node("xor", value, mask, width=width),
            width=width,
        ),
        _node(
            "mul",
            _constant(2, width=width),
            _node("bnot", _node("or", value, mask, width=width), width=width),
            width=width,
        ),
        width=width,
    )

    _assert_exact_eid_candidate_matches(
        "xor", Xor_EidComplementConsensus_1, candidate
    )


def test_eid_complement_partition_1_matches_exact_64_bit_source_tree() -> None:
    width = 64
    x = _leaf("x", width=width)
    c_left = _constant(0xF500C38D0EA2975A, width=width)
    c_right = _constant(0x0AFF3C72F15D68A5, width=width)
    right_minus_one = _constant(0x0AFF3C72F15D68A4, width=width)

    candidate = _node(
        "sub",
        _node(
            "sub",
            _node(
                "add",
                _node(
                    "add",
                    _node(
                        "add",
                        _node(
                            "mul",
                            _constant(8, width=width),
                            _node("bnot", _node("or", x, c_left, width=width), width=width),
                            width=width,
                        ),
                        _node("or", x, c_left, width=width),
                        width=width,
                    ),
                    _node("and", x, c_right, width=width),
                    width=width,
                ),
                _node(
                    "mul",
                    _constant(6, width=width),
                    _node("and", x, c_left, width=width),
                    width=width,
                ),
                width=width,
            ),
            right_minus_one,
            width=width,
        ),
        _node(
            "mul",
            _constant(5, width=width),
            _node("xor", x, c_right, width=width),
            width=width,
        ),
        width=width,
    )

    _assert_exact_eid_xor_candidate_matches(Xor_EidComplementPartition_1, candidate)


def test_eid_complement_partition_2_matches_exact_64_bit_source_tree() -> None:
    width = 64
    x = _leaf("x", width=width)
    c_left = _constant(0x4C8ADE951AD35D8C, width=width)
    c_right = _constant(0xB375216AE52CA273, width=width)

    candidate = _node(
        "sub",
        _node(
            "add",
            _node(
                "add",
                _node(
                    "add",
                    _node(
                        "mul",
                        _constant(6, width=width),
                        _node("bnot", _node("or", x, c_left, width=width), width=width),
                        width=width,
                    ),
                    _node("xor", x, c_left, width=width),
                    width=width,
                ),
                _node(
                    "mul",
                    _constant(6, width=width),
                    _node("and", x, c_right, width=width),
                    width=width,
                ),
                width=width,
            ),
            _node(
                "mul",
                _constant(6, width=width),
                _node("and", x, c_left, width=width),
                width=width,
            ),
            width=width,
        ),
        _node(
            "mul",
            _constant(6, width=width),
            _node("or", x, c_right, width=width),
            width=width,
        ),
        width=width,
    )

    _assert_exact_eid_xor_candidate_matches(Xor_EidComplementPartition_2, candidate)


def test_eid_complement_partition_3_matches_unsigned_minus_8_source_tree() -> None:
    width = 64
    x = _leaf("x", width=width)
    mask = _constant(0x3C33682BB7D99927, width=width)

    candidate = _node(
        "sub",
        _constant(0xFFFFFFFFFFFFFFF8, width=width),
        _node(
            "add",
            _node(
                "add",
                _node(
                    "add",
                    _node("and", x, mask, width=width),
                    _node(
                        "mul",
                        _constant(6, width=width),
                        _node("or", x, mask, width=width),
                        width=width,
                    ),
                    width=width,
                ),
                _node(
                    "mul",
                    _constant(8, width=width),
                    _node("bnot", _node("or", x, mask, width=width), width=width),
                    width=width,
                ),
                width=width,
            ),
            _node("or", x, mask, width=width),
            width=width,
        ),
        width=width,
    )

    _assert_exact_eid_xor_candidate_matches(Xor_EidComplementPartition_3, candidate)


def test_shared_feasibility_filter_preserves_later_match_under_tight_budget() -> None:
    """Impossible earlier patterns must not consume the shared budget in either mode."""

    rules = _compile_rule_families(
        {"add": (_ImpossibleBeforeValidRule, _ValidAfterImpossibleRule)}
    ).compiled_rules
    catalogue = CompiledPatternCatalogue.from_rules(rules)
    candidate = _node("add", _leaf("x"), _constant(0))

    result = catalogue._match_root_portable(candidate, comparison_budget=5)

    assert result.comparison_budget_exceeded is False
    assert tuple(match.rule.source_name for match in result.matches) == (
        "_ValidAfterImpossibleRule",
    )


@pytest.mark.parametrize("operation", ("shl", "lshr"))
def test_pod_adapter_falls_back_for_fixed_shift_child(
    monkeypatch, operation: str
) -> None:
    """Unsupported fixed-shift packing must retain the portable root match."""

    monkeypatch.setattr(VerifiableRule, "registry", dict(VerifiableRule.registry))
    left, right = Var("fallback_left"), Var("fallback_right")

    class _WildcardRootRule(VerifiableRule):
        PATTERN = left + right
        REPLACEMENT = PATTERN

    rules = _compile_rule_families({"add": (_WildcardRootRule,)}).compiled_rules
    catalogue = CompiledPatternCatalogue.from_rules(rules)
    shifted = NativeMbaTermView(
        operation,
        32,
        children=(_leaf("x"),),
        shift_count=1,
    )
    candidate = _node("add", shifted, _leaf("y"))

    portable = catalogue._match_root_portable(candidate, comparison_budget=64)
    pod = match_root_pod(catalogue, candidate, comparison_budget=64)

    assert pod == portable
    assert tuple(match.rule.source_name for match in pod.matches) == (
        "_WildcardRootRule",
    )


@pytest.mark.parametrize("operation", ("shl", "lshr"))
def test_portable_repeated_binding_distinguishes_fixed_shift_counts(
    monkeypatch, operation: str
) -> None:
    """Repeated bindings compare fixed-shift metadata, not only child shape."""

    monkeypatch.setattr(VerifiableRule, "registry", dict(VerifiableRule.registry))
    value = Var("repeated_value")

    class _RepeatedBindingRule(VerifiableRule):
        PATTERN = value + value
        REPLACEMENT = PATTERN

    rules = _compile_rule_families({"add": (_RepeatedBindingRule,)}).compiled_rules
    catalogue = CompiledPatternCatalogue.from_rules(rules)

    def shifted(count: int) -> NativeMbaTermView:
        return NativeMbaTermView(
            operation,
            32,
            children=(_leaf("shared"),),
            shift_count=count,
        )

    different_counts = catalogue._match_root_portable(
        _node("add", shifted(1), shifted(2)),
        comparison_budget=64,
    )
    identical_counts = catalogue._match_root_portable(
        _node("add", shifted(1), shifted(1)),
        comparison_budget=64,
    )

    assert different_counts.matches == ()
    assert tuple(match.rule.source_name for match in identical_counts.matches) == (
        "_RepeatedBindingRule",
    )
