from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import FrozenInstanceError, fields

import pytest

from d810.mba.egglog_composite_rewrite import (
    ACTIVE_SEMANTICS_SCHEMA_VERSION,
    MAX_INPUT_LEAF_SLOTS,
    MAX_SERIALIZED_ENTRY_BYTES,
    ActiveSemantics,
    AlphaTerm,
    CompositeRewriteMalformed,
    EgglogCompositeRewrite,
)
from d810.mba.typed_term import TypedBvTerm, fixed_shift_term


WIDTH = 32
CATALOGUE_DIGEST = "a" * 64
PROFILE_DIGEST = "b" * 64


def leaf(name: str, *, width: int = WIDTH, kind: str = "register") -> TypedBvTerm:
    return TypedBvTerm(None, width, leaf_key=(kind, name))


def const(value: int, *, width: int = WIDTH) -> TypedBvTerm:
    return TypedBvTerm(None, width, value=value)


def unary(operation: str, child: TypedBvTerm) -> TypedBvTerm:
    return TypedBvTerm(operation, child.width, children=(child,))


def binary(
    operation: str, left: TypedBvTerm, right: TypedBvTerm
) -> TypedBvTerm:
    return TypedBvTerm(operation, left.width, children=(left, right))


@pytest.fixture
def semantics() -> ActiveSemantics:
    return ActiveSemantics(
        canonicalizer_version=1,
        catalogue_digest=CATALOGUE_DIGEST,
        profile_digest=PROFILE_DIGEST,
        egglog_version="13.2.0",
        proof_mode="shadow",
        active_rule_names=(
            ("add", "R"),
            ("add", "R2"),
            ("xor", "XorRule"),
        ),
    )


@pytest.fixture
def valid_rewrite(semantics: ActiveSemantics) -> EgglogCompositeRewrite:
    x = leaf("x")
    # Keep the source term strictly more expensive while exercising a repeated
    # source leaf and a literal in the output.
    source = binary("add", binary("add", x, x), x)
    output = binary("mul", const(3), x)
    return EgglogCompositeRewrite.from_extraction(
        input_term=source,
        output_term=output,
        derivation_trace=(("add", "R", ()),),
        semantics=semantics,
    )


def test_alpha_term_is_frozen_and_slotted() -> None:
    assert all(field.name != "__dict__" for field in fields(AlphaTerm))
    term = AlphaTerm(width=32, leaf_slot=0)
    with pytest.raises(FrozenInstanceError):
        term.width = 64  # type: ignore[misc]


def test_composite_rebinds_current_live_leaf_shape(semantics: ActiveSemantics) -> None:
    x = leaf("x")
    source = binary("add", binary("add", x, x), x)
    output = binary("mul", const(3), x)
    learned = EgglogCompositeRewrite.from_extraction(
        input_term=source,
        output_term=output,
        derivation_trace=(("add", "R", ()),),
        semantics=semantics,
    )

    y = leaf("y")
    bindings = learned.match(
        binary("add", binary("add", y, y), y), semantics=semantics
    )

    assert bindings is not None
    assert learned.materialize(bindings, semantics=semantics) == binary(
        "mul", const(3), y
    )


def test_composite_rejects_changed_alias_shape(
    valid_rewrite: EgglogCompositeRewrite,
    semantics: ActiveSemantics,
) -> None:
    y = leaf("y")
    z = leaf("z")
    assert (
        valid_rewrite.match(
            binary("add", binary("add", y, z), y), semantics=semantics
        )
        is None
    )


def test_match_is_transactional_and_deterministic(
    valid_rewrite: EgglogCompositeRewrite,
    semantics: ActiveSemantics,
) -> None:
    y = leaf("y")
    candidate = binary("add", binary("add", y, y), y)
    first = valid_rewrite.match(candidate, semantics=semantics)
    second = valid_rewrite.match(candidate, semantics=semantics)
    assert first == second
    assert first is not None
    first[0] = leaf("tampered")
    assert valid_rewrite.match(candidate, semantics=semantics) == {0: y}


def test_composite_json_is_stable_across_round_trip(
    valid_rewrite: EgglogCompositeRewrite,
) -> None:
    encoded = valid_rewrite.to_json()
    decoded = EgglogCompositeRewrite.from_json(encoded)
    assert decoded == valid_rewrite
    assert decoded.to_json() == encoded
    assert encoded == json.dumps(
        valid_rewrite.to_dict(), sort_keys=True, separators=(",", ":")
    )


def test_serialized_schema_is_exact_and_json_safe(
    valid_rewrite: EgglogCompositeRewrite,
) -> None:
    assert set(valid_rewrite.to_dict()) == {
        "schema_version",
        "template_id",
        "canonicalizer_version",
        "catalogue_digest",
        "profile_digest",
        "egglog_version",
        "proof_mode",
        "width",
        "root_operation",
        "coarse_arity",
        "input_template",
        "output_template",
        "raw_input_cost",
        "output_cost",
        "derivation_trace",
        "created_sequence",
        "last_used_sequence",
    }
    assert json.loads(valid_rewrite.to_json()) == valid_rewrite.to_dict()


def _payload_mutation(
    rewrite: EgglogCompositeRewrite,
    mutation: str,
) -> dict[str, object]:
    payload = deepcopy(rewrite.to_dict())
    if mutation == "unknown_schema":
        payload["schema_version"] = ACTIVE_SEMANTICS_SCHEMA_VERSION + 99
    elif mutation == "unknown_operation":
        payload["input_template"]["operation"] = "call"  # type: ignore[index]
    elif mutation == "output_uses_unknown_slot":
        payload["output_template"]["leaf_slot"] = MAX_INPUT_LEAF_SLOTS  # type: ignore[index]
        payload["output_template"]["operation"] = None  # type: ignore[index]
        payload["output_template"]["value"] = None  # type: ignore[index]
        payload["output_template"]["children"] = []  # type: ignore[index]
    elif mutation == "non_strict_cost":
        payload["output_cost"] = payload["raw_input_cost"]
    elif mutation == "empty_trace":
        payload["derivation_trace"] = []
    elif mutation == "wrong_catalogue_digest":
        payload["catalogue_digest"] = "c" * 64
    elif mutation == "raw_mop_key_in_payload":
        payload["input_template"]["leaf_key"] = ["mop", "x"]  # type: ignore[index]
    else:  # pragma: no cover - test helper guard
        raise AssertionError(mutation)
    return payload


@pytest.mark.parametrize(
    "mutation",
    [
        "unknown_schema",
        "unknown_operation",
        "output_uses_unknown_slot",
        "non_strict_cost",
        "empty_trace",
        "wrong_catalogue_digest",
        "raw_mop_key_in_payload",
    ],
)
def test_composite_payload_validation_fails_closed(
    valid_rewrite: EgglogCompositeRewrite,
    semantics: ActiveSemantics,
    mutation: str,
) -> None:
    payload = _payload_mutation(valid_rewrite, mutation)
    with pytest.raises(CompositeRewriteMalformed):
        EgglogCompositeRewrite.from_dict(payload, semantics=semantics)


def test_from_json_rejects_malformed_json(valid_rewrite: EgglogCompositeRewrite) -> None:
    with pytest.raises(CompositeRewriteMalformed):
        EgglogCompositeRewrite.from_json("not-json")


def test_stale_semantics_are_rejected(
    valid_rewrite: EgglogCompositeRewrite,
    semantics: ActiveSemantics,
) -> None:
    stale = ActiveSemantics(
        canonicalizer_version=semantics.canonicalizer_version,
        catalogue_digest="c" * 64,
        profile_digest=semantics.profile_digest,
        egglog_version=semantics.egglog_version,
        proof_mode=semantics.proof_mode,
        active_rule_names=semantics.active_rule_names,
    )
    with pytest.raises(CompositeRewriteMalformed):
        EgglogCompositeRewrite.from_json(valid_rewrite.to_json(), semantics=stale)


def test_missing_derivation_rule_is_rejected(semantics: ActiveSemantics) -> None:
    x = leaf("x")
    with pytest.raises(CompositeRewriteMalformed):
        EgglogCompositeRewrite.from_extraction(
            input_term=binary("add", binary("add", x, x), x),
            output_term=binary("mul", const(3), x),
            derivation_trace=(("add", "missing", ()),),
            semantics=semantics,
        )


def test_too_many_input_leaves_is_rejected(semantics: ActiveSemantics) -> None:
    leaves = [leaf(str(index)) for index in range(MAX_INPUT_LEAF_SLOTS + 1)]
    source = leaves[0]
    for item in leaves[1:]:
        source = binary("add", source, item)
    with pytest.raises(CompositeRewriteMalformed):
        EgglogCompositeRewrite.from_extraction(
            input_term=source,
            output_term=leaves[0],
            derivation_trace=(("add", "R", ()),),
            semantics=semantics,
        )


def test_native_shaped_leaf_key_is_local_only_and_rebinds(
    semantics: ActiveSemantics,
) -> None:
    x = leaf("x", kind="mop")
    learned = EgglogCompositeRewrite.from_extraction(
        input_term=binary("add", binary("add", x, x), x),
        output_term=binary("mul", const(3), x),
        derivation_trace=(("add", "R", ()),),
        semantics=semantics,
    )
    assert "mop" not in learned.to_json()

    y = leaf("y", kind="mop")
    candidate = binary("add", binary("add", y, y), y)
    bindings = learned.match(candidate, semantics=semantics)
    assert bindings == {0: y}
    assert learned.materialize(bindings, semantics=semantics) == binary(
        "mul", const(3), y
    )


def test_supported_fixed_shift_preserves_literal_count(
    semantics: ActiveSemantics,
) -> None:
    x = leaf("x")
    source = binary(
        "add",
        fixed_shift_term("shl", WIDTH, x, 3),
        fixed_shift_term("lshr", WIDTH, x, 29),
    )
    output = fixed_shift_term("rol", WIDTH, x, 3)
    rewrite = EgglogCompositeRewrite.from_extraction(
        input_term=source,
        output_term=output,
        derivation_trace=(("add", "R2", ()),),
        semantics=semantics,
    )
    y = leaf("y")
    candidate = binary(
        "add",
        fixed_shift_term("shl", WIDTH, y, 3),
        fixed_shift_term("lshr", WIDTH, y, 29),
    )
    bindings = rewrite.match(candidate, semantics=semantics)
    assert rewrite.materialize(bindings, semantics=semantics) == fixed_shift_term(
        "rol", WIDTH, y, 3
    )


def test_widths_are_limited_to_fixed_portable_widths(
    semantics: ActiveSemantics,
) -> None:
    x = leaf("x", width=24)
    with pytest.raises(CompositeRewriteMalformed):
        EgglogCompositeRewrite.from_extraction(
            input_term=binary("add", binary("add", x, x), x),
            output_term=binary("mul", const(3, width=24), x),
            derivation_trace=(("add", "R", ()),),
            semantics=semantics,
        )


def test_serialized_entry_has_hard_size_bound(
    valid_rewrite: EgglogCompositeRewrite,
) -> None:
    assert len(valid_rewrite.to_json().encode("utf-8")) <= MAX_SERIALIZED_ENTRY_BYTES


def test_materialize_requires_current_typed_bindings(
    valid_rewrite: EgglogCompositeRewrite,
    semantics: ActiveSemantics,
) -> None:
    with pytest.raises(CompositeRewriteMalformed):
        valid_rewrite.materialize({0: object()}, semantics=semantics)
    with pytest.raises(CompositeRewriteMalformed):
        valid_rewrite.materialize({}, semantics=semantics)


def test_semantics_descriptor_is_json_safe(semantics: ActiveSemantics) -> None:
    encoded = semantics.to_json()
    assert json.loads(encoded) == semantics.to_dict()
    assert ActiveSemantics.from_json(encoded) == semantics


def test_semantics_requires_exact_frozenset_rule_pairs() -> None:
    descriptor = ActiveSemantics(
        canonicalizer_version=1,
        catalogue_digest=CATALOGUE_DIGEST,
        profile_digest=PROFILE_DIGEST,
        egglog_version="13.2.0",
        proof_mode="legacy",
        active_rule_names=frozenset({("add", "R")}),
    )
    assert descriptor.has_rule("add", "R")
    assert not descriptor.has_rule("xor", "R")
    with pytest.raises(ValueError):
        ActiveSemantics(
            canonicalizer_version=1,
            catalogue_digest=CATALOGUE_DIGEST,
            profile_digest=PROFILE_DIGEST,
            egglog_version="13.2.0",
            proof_mode="legacy",
            active_rule_names=frozenset({"R"}),
        )


def test_trace_requires_exact_rule_family_and_source(
    semantics: ActiveSemantics,
) -> None:
    x = leaf("x")
    with pytest.raises(CompositeRewriteMalformed):
        EgglogCompositeRewrite.from_extraction(
            input_term=binary("add", binary("add", x, x), x),
            output_term=binary("mul", const(3), x),
            derivation_trace=(("xor", "R", ()),),
            semantics=semantics,
        )


def test_syntax_only_decode_cannot_replay_without_current_semantics(
    valid_rewrite: EgglogCompositeRewrite,
) -> None:
    decoded = EgglogCompositeRewrite.from_json(valid_rewrite.to_json())
    y = leaf("y")
    candidate = binary("add", binary("add", y, y), y)
    with pytest.raises(CompositeRewriteMalformed):
        decoded.match(candidate)
    with pytest.raises(CompositeRewriteMalformed):
        decoded.materialize({0: y})
