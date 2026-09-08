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


def test_owned_group_projection_returns_canonical_bytes_and_complete_id_map():
    proofs = (_proof(), _storage_choice_proof())
    arena = RuntimeAuthorityArena(RuntimeAuthorityScope("group-boundary"))
    entries = tuple(
        (
            f"runtime-proof-{index}",
            routes.capture_structural_route_proof(arena.structural, proof),
            proof.diagnostic_provenance,
        )
        for index, proof in enumerate(proofs)
    )
    arena.structural.publish()
    projection = routes.project_owned_route_group(
        arena.structural,
        3,
        "runtime-group",
        entries,
    )
    expected = routes.canonical_semantic_evidence_from_proofs(
        proofs[0].source_identity.native_key,
        3,
        proofs,
    )
    assert canonical_bytes(projection.evidence) == canonical_bytes(expected)
    assert projection.evidence.route_binding is None
    assert projection.evidence.runtime_identity is None
    assert projection.group_id_pair == ("runtime-group", expected.atomic_group_id)
    assert projection.proof_id_pairs == tuple(
        (
            f"runtime-proof-{index}",
            routes._canonical_route_proof_id(
                atomic_group_id=expected.atomic_group_id, proof=proof
            ),
        )
        for index, proof in enumerate(proofs)
    )


@pytest.mark.parametrize("fail_after_factory", (False, True))
def test_group_projection_closes_only_its_temporary_join_arena(
    monkeypatch, fail_after_factory
):
    minted = []
    mint = routes._mint_route_binding
    factory = routes.canonical_semantic_evidence_from_proofs

    def record_mint(arena, **kwargs):
        minted.append(arena)
        return mint(arena, **kwargs)

    def fail_after_mint(*args, **kwargs):
        factory(*args, **kwargs)
        raise ValueError("injected after canonical mint")

    monkeypatch.setattr(routes, "_mint_route_binding", record_mint)
    if fail_after_factory:
        monkeypatch.setattr(
            routes, "canonical_semantic_evidence_from_proofs", fail_after_mint
        )
    with routes.route_authority_phase("source-owner") as owner:
        arena = RuntimeAuthorityArena(RuntimeAuthorityScope("source"))
        owner.adopt(arena)
        ref = routes.capture_structural_route_proof(arena.structural, _proof())
        entries = (("source-proof", ref, ()),)
        if fail_after_factory:
            with pytest.raises(ValueError, match="injected after canonical mint"):
                routes.project_owned_route_group(
                    arena.structural, 3, "source-group", entries
                )
        else:
            routes.project_owned_route_group(
                arena.structural, 3, "source-group", entries
            )
        assert not arena.is_closed
        assert len(minted) == 1
        assert minted[0] is not arena and minted[0].is_closed


def test_group_projection_maps_every_duplicate_payload_and_rejects_ambiguous_ids():
    arena = RuntimeAuthorityArena(RuntimeAuthorityScope("source"))
    ref = routes.capture_structural_route_proof(arena.structural, _proof())
    entries = (
        ("first", ref, (("source", "first"),)),
        ("second", ref, (("source", "second"),)),
    )
    projected = routes.project_owned_route_group(arena.structural, 3, "group", entries)
    assert len(projected.evidence.route_proofs) == 1
    canonical_id = projected.evidence.route_proofs[0].proof_id
    assert projected.proof_id_pairs == (
        ("first", canonical_id),
        ("second", canonical_id),
    )
    assert projected.evidence.route_proofs[0].diagnostic_provenance == (
        ("source", "first"),
        ("source", "second"),
    )
    reversed_projection = routes.project_owned_route_group(
        arena.structural, 3, "group", tuple(reversed(entries))
    )
    assert canonical_bytes(reversed_projection.evidence) == canonical_bytes(
        projected.evidence
    )
    with pytest.raises(ValueError, match="duplicate source proof IDs"):
        routes.project_owned_route_group(
            arena.structural, 3, "group", (entries[0], entries[0])
        )
