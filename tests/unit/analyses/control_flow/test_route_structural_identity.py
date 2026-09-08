"""Owned route terms detach descendants without changing canonical validation."""

from dataclasses import fields, is_dataclass, replace
from d810.core.typing import get_args, get_type_hints
from d810.transforms.unflatten_authority.ids import canonical_bytes, canonical_decode

import pytest

from d810.analyses.control_flow import semantic_route_evidence as routes
from d810.core.runtime_identity import RuntimeAuthorityArena, RuntimeAuthorityScope
from d810.core.structural_identity import StructuralIdentityError, compare_values
from tests.unit.analyses.control_flow.test_semantic_route_evidence import (
    _proof,
    _native_bound_production_inputs,
    _storage_choice_proof,
)


def test_route_capture_ignores_only_top_level_ids_and_diagnostics(monkeypatch):
    proof = _proof()
    relabeled = replace(
        proof,
        proof_id="other",
        atomic_group_id="group",
        diagnostic_provenance=(("label", "different"),),
    )
    left = RuntimeAuthorityArena(RuntimeAuthorityScope("left"))
    right = RuntimeAuthorityArena(RuntimeAuthorityScope("right"))
    monkeypatch.setattr(
        routes, "_fingerprint_value", lambda value: pytest.fail("codec")
    )
    a = routes.capture_structural_route_proof(left.structural, proof)
    b = routes.capture_structural_route_proof(right.structural, relabeled)
    assert compare_values(left.structural, a, right.structural, b)
    assert not compare_values(
        left.structural,
        a,
        right.structural,
        routes.capture_structural_route_proof(
            right.structural, _storage_choice_proof()
        ),
    )
    owned = left.structural
    left.close()
    with pytest.raises(StructuralIdentityError):
        owned.resolve(a, a.kind)


def test_declared_route_record_descendants_have_explicit_field_census():
    seen = set()
    records = set()

    def visit(record_type):
        if record_type in seen:
            return
        seen.add(record_type)
        if isinstance(record_type, type) and is_dataclass(record_type):
            records.add(record_type)
            assert routes._ROUTE_STRUCTURAL_FIELDS[record_type] == tuple(
                field.name for field in fields(record_type)
            )
            hints = get_type_hints(record_type)
            for field in fields(record_type):
                visit(hints[field.name])
        else:
            for argument in get_args(record_type):
                visit(argument)

    visit(routes.SemanticRouteProof)
    assert records == set(routes._ROUTE_STRUCTURAL_FIELDS)


def _physical_proof_with_attrs(attrs):
    fact, context = _native_bound_production_inputs()
    evidence = routes.build_canonical_semantic_evidence((fact,), context).evidence
    assert evidence is not None
    proof = evidence.route_proofs[0]
    write = proof.state_write
    physical = write.physical_state_write
    return replace(
        proof,
        state_write=replace(
            write,
            physical_state_write=replace(
                physical,
                source_instruction=replace(
                    physical.source_instruction, opcode_attrs=attrs
                ),
            ),
        ),
    )


def test_capture_detaches_real_instruction_attribute_aliases():
    aliases = [1, {"value": 2}]
    proof = _physical_proof_with_attrs({"custom": aliases})
    left = RuntimeAuthorityArena(RuntimeAuthorityScope("capture"))
    right = RuntimeAuthorityArena(RuntimeAuthorityScope("comparison"))
    owned = routes.capture_structural_route_proof(left.structural, proof)
    expected = routes.capture_structural_route_proof(
        right.structural,
        _physical_proof_with_attrs({"custom": [1, {"value": 2}]}),
    )
    aliases[1]["value"] = 3
    assert compare_values(left.structural, owned, right.structural, expected)
    changed = routes.capture_structural_route_proof(right.structural, proof)
    assert not compare_values(left.structural, owned, right.structural, changed)


def test_capture_rejects_opaque_attribute_values_and_cycles():
    cycle = []
    cycle.append(cycle)
    for value, error in ((object(), TypeError), (cycle, ValueError)):
        arena = RuntimeAuthorityArena(RuntimeAuthorityScope("rejection"))
        with pytest.raises(error):
            routes.capture_structural_route_proof(
                arena.structural,
                _physical_proof_with_attrs({"custom": value}),
            )


@pytest.mark.parametrize("factory", (_proof, _storage_choice_proof))
def test_owned_route_projection_preserves_canonical_payload(factory):
    original = factory()
    arena = RuntimeAuthorityArena(RuntimeAuthorityScope("boundary"))
    ref = routes.capture_structural_route_proof(arena.structural, original)
    projected = routes.materialize_structural_route_proof(
        arena.structural,
        ref,
        proof_id=original.proof_id,
        atomic_group_id=original.atomic_group_id,
        diagnostic_provenance=original.diagnostic_provenance,
    )
    assert projected is not original
    assert canonical_bytes(projected) == canonical_bytes(original)
    assert routes._stable_route_proof_payload(
        projected
    ) == routes._stable_route_proof_payload(original)
    assert (
        routes.canonical_semantic_evidence_from_proofs(
            original.source_identity.native_key,
            3,
            (projected,),
        ).atomic_group_id
        == routes.canonical_semantic_evidence_from_proofs(
            original.source_identity.native_key,
            3,
            (original,),
        ).atomic_group_id
    )


def test_owned_projection_keeps_existing_physical_write_constructor_rejection():
    proof = _physical_proof_with_attrs({})
    object.__setattr__(proof.state_write.physical_state_write, "state_lane_offset", 1)
    arena = RuntimeAuthorityArena(RuntimeAuthorityScope("invalid-boundary"))
    ref = routes.capture_structural_route_proof(arena.structural, proof)
    # Capture represents a value; it never claims that the value was validated.
    with pytest.raises(ValueError):
        canonical_decode(canonical_bytes(proof))
    with pytest.raises(
        routes.SemanticRouteEvidenceRejected, match="little-endian U32 lane"
    ):
        routes.materialize_structural_route_proof(
            arena.structural,
            ref,
            proof_id=proof.proof_id,
            atomic_group_id=proof.atomic_group_id,
            diagnostic_provenance=proof.diagnostic_provenance,
        )
