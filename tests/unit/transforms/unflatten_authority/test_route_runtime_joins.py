"""The route-group -> proof join keys on arena references, not content IDs.

The authority question a membership join asks is "is this exact record a proof
of this exact bundle".  These tests pin that it is answered by the arena, that
it costs no canonical encoding, and that the two boundaries which must stay
content-keyed forever really do.
"""

from __future__ import annotations

import copy
from dataclasses import replace

import pytest

import d810.transforms.unflatten_authority.bind as bind
import d810.transforms.unflatten_authority.ids as authority_ids
import d810.analyses.control_flow.semantic_route_evidence as route_evidence
from d810.analyses.control_flow.semantic_route_evidence import (
    CanonicalSemanticEvidence,
    SemanticRouteDestination,
    SemanticRouteProof,
    SemanticRouteProofKind,
    SemanticRouteShape,
    SemanticStateWriteProof,
    bind_route_evidence,
    canonical_semantic_evidence_from_proofs,
    materialize_route_evidence,
    route_authority_phase,
    route_join_binding,
    runtime_semantic_route_scope,
)
from d810.core.runtime_identity import (
    RUNTIME_AUTHORITY_SIDECAR_FIELDS,
    RuntimeAuthorityArena,
    RuntimeAuthorityArenaError,
    RuntimeAuthorityKind,
    RuntimeJoinRejected,
)
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
import d810.transforms.unflatten_authority.model as model
import d810.transforms.unflatten_authority.producer_api as producer_api
from d810.transforms.unflatten_authority.producer_api import bundle_route_proof_refs
from tests.native_preanalysis import make_native_key

from d810.transforms.unflatten_authority.evaluate import build_semantic_case

from .helpers import exact_fixture
from .test_evaluate import _complete_inputs, _role_subject, _with_entry_gate_facts

NATIVE_KEY = make_native_key(function_rva=0x1000)


def _identity(ea: int) -> StableBlockIdentity:
    return StableBlockIdentity.from_intervals(
        (NativeEaInterval(ea, ea + 0x10),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(ea,),
    )


def _proof(ea: int = 0x1100, state: int = 0xAABBCCDD) -> SemanticRouteProof:
    source = _identity(ea)
    return SemanticRouteProof(
        proof_id=f"state-assignment@{ea:#x}",
        atomic_group_id="producer-label:g3",
        proof_kind=SemanticRouteProofKind.STATE_ASSIGNMENT,
        shape=SemanticRouteShape.DIRECT,
        source_identity=source,
        source_anchor_ea=ea,
        delivery_region=NativeEaInterval(ea, ea + 1),
        destinations=(
            SemanticRouteDestination(
                role=SemanticEdgeRole.DIRECT,
                state_constant=state,
                target_identity=_identity(ea + 0x100),
                target_anchor_ea=ea + 0x100,
            ),
        ),
        state_write=SemanticStateWriteProof(
            identity=source,
            instruction_ea=ea,
            state_variable=StorageIdentity(StorageIdentityKind.REGISTER, 20),
            width=4,
            state_constant=state,
            corridor_instruction_eas=(ea,),
            authority_transfer_ea=None,
            preserved_call_instruction_eas=(),
        ),
    )


def _bundle() -> CanonicalSemanticEvidence:
    return canonical_semantic_evidence_from_proofs(
        NATIVE_KEY, 3, (_proof(), _proof(0x1400, 0x11223344)),
    )


REJECTION = "selected route proof is foreign to canonical evidence"


def test_membership_join_returns_one_reference_per_bundle_proof() -> None:
    evidence = _bundle()

    refs = bundle_route_proof_refs(
        evidence, evidence.route_proofs, rejection=REJECTION,
    )

    assert len(refs) == len(evidence.route_proofs)
    assert all(ref.kind is RuntimeAuthorityKind.ROUTE_PROOF for ref in refs)
    assert len(set(refs)) == len(refs)


def test_membership_join_refuses_a_content_equal_copy() -> None:
    """The join is about identity; a copy has the same content and no authority."""

    evidence = _bundle()
    copy = replace(evidence.route_proofs[0])

    assert copy == evidence.route_proofs[0]
    assert copy.proof_id == evidence.route_proofs[0].proof_id
    with pytest.raises(ValueError, match=REJECTION):
        bundle_route_proof_refs(evidence, (copy,), rejection=REJECTION)


def test_membership_join_refuses_a_proof_from_another_bundle() -> None:
    first = _bundle()
    second = _bundle()

    assert first == second
    with pytest.raises(ValueError, match=REJECTION):
        bundle_route_proof_refs(
            first, (second.route_proofs[0],), rejection=REJECTION,
        )


def test_membership_join_costs_no_canonical_encoding(monkeypatch) -> None:
    """The whole point: joining must not walk or hash a record graph."""

    evidence = _bundle()

    def refuse(*args: object, **kwargs: object) -> bytes:
        raise AssertionError("a runtime join must not encode canonical bytes")

    monkeypatch.setattr(authority_ids, "canonical_bytes", refuse)
    monkeypatch.setattr(authority_ids, "_record_content_id", refuse)

    refs = bundle_route_proof_refs(
        evidence, evidence.route_proofs, rejection=REJECTION,
    )

    assert len(refs) == len(evidence.route_proofs)


def test_an_unbound_bundle_cannot_be_joined_at_all() -> None:
    evidence = _bundle()
    unbound = materialize_route_evidence(evidence)

    # The binding accessor states the real reason...
    with pytest.raises(RuntimeJoinRejected, match="not bound"):
        route_join_binding(unbound)
    # ...and the package boundary reports it in the vocabulary its callers,
    # including the emitter's abstention handler, already catch.
    with pytest.raises(ValueError, match=REJECTION):
        bundle_route_proof_refs(
            unbound, unbound.route_proofs, rejection=REJECTION,
        )


def test_rebinding_an_unbound_bundle_makes_the_join_available_again() -> None:
    evidence = _bundle()
    unbound = materialize_route_evidence(evidence)
    arena = RuntimeAuthorityArena(runtime_semantic_route_scope(NATIVE_KEY, 3))

    rebound = bind_route_evidence(unbound, arena=arena)

    refs = bundle_route_proof_refs(
        rebound, rebound.route_proofs, rejection=REJECTION,
    )
    assert len(refs) == len(rebound.route_proofs)
    # The rebind moved no content: the fingerprints are the ones the producer
    # minted, and they are still reproducible from the bundle's own bytes.
    assert authority_ids.canonical_bytes(rebound) == authority_ids.canonical_bytes(
        evidence
    )
    # ...and the two arenas are two authorities over one value: neither
    # inherits the other's references, even though both name the same records.
    assert refs != bundle_route_proof_refs(
        evidence, evidence.route_proofs, rejection=REJECTION,
    )


def test_ingestion_dedup_stays_content_keyed() -> None:
    """Producer inputs have no arena yet, so their merge is a content merge.

    ``_canonical_authoritative_proofs`` runs *before* any identity is minted:
    its inputs carry producer labels, not canonical IDs and not references.
    There is nothing for a reference to key on, so this boundary is
    content-keyed by construction and must stay that way.
    """

    proof = _proof()
    labelled = replace(proof, diagnostic_provenance=(("fact_id", "a"),))
    other = replace(proof, diagnostic_provenance=(("fact_id", "b"),))

    merged = canonical_semantic_evidence_from_proofs(
        NATIVE_KEY, 3, (labelled, other),
    )

    assert len(merged.route_proofs) == 1
    assert merged.route_proofs[0].diagnostic_provenance == (
        ("fact_id", "a"), ("fact_id", "b"),
    )


def test_canonical_proof_id_uniqueness_stays_a_content_check() -> None:
    """Fingerprint uniqueness is a content invariant, not an authority join.

    Two bundle proofs may never share a content ID -- that would mean the
    bundle's own fingerprints do not identify its content.  A reference-keyed
    version of this check is vacuous, because references are unique by
    construction, so it must keep reading the content ID.
    """

    evidence = _bundle()
    forged = object.__new__(CanonicalSemanticEvidence)
    duplicated = (evidence.route_proofs[0], evidence.route_proofs[0])
    object.__setattr__(forged, "native_key", evidence.native_key)
    object.__setattr__(forged, "generation", evidence.generation)
    object.__setattr__(forged, "atomic_group_id", evidence.atomic_group_id)
    object.__setattr__(forged, "route_proofs", duplicated)
    object.__setattr__(forged, "_runtime_identity", None)
    object.__setattr__(forged, "_runtime_binding", None)

    with pytest.raises(Exception, match="duplicate proof ids"):
        CanonicalSemanticEvidence.__post_init__(forged)


def test_registry_snapshot_and_detached_copy_ignore_the_runtime_sidecar() -> None:
    """The registry seal covers the canonical schema, never a live arena.

    ``bind._registry_structural_snapshot`` and ``bind._detached_canonical_copy``
    enumerate ``dataclasses.fields`` rather than the canonical schema, so they
    would otherwise see a sidecar holding an arena: the snapshot has no
    representation for it and a detached copy must not duplicate it.  Both
    skip it, which makes a bound and an unbound bundle produce the same seal
    and makes every detached copy unbound.
    """

    evidence = _bundle()
    unbound = materialize_route_evidence(evidence)

    assert bind._registry_structural_snapshot(
        evidence
    ) == bind._registry_structural_snapshot(unbound)

    detached = bind._detached_canonical_copy(evidence, {})

    assert type(detached) is CanonicalSemanticEvidence
    assert detached.route_binding is None
    assert detached == evidence


def test_the_sidecar_skip_cannot_reach_a_canonical_field() -> None:
    """The closed name set is the guard; prove it excludes nothing canonical."""

    tables = {**authority_ids._RECORD_FIELDS, **authority_ids._EXTERNAL_FIELDS}
    canonical_names = {name for names in tables.values() for name in names}

    assert not (canonical_names & RUNTIME_AUTHORITY_SIDECAR_FIELDS)
    assert not any(name.startswith("_") for name in canonical_names)


def test_the_translation_boundary_covers_an_unbound_and_a_closed_bundle() -> None:
    """Every join refusal leaves this function as the package's ``ValueError``.

    Resolving the binding used to happen before the translating ``try``, so an
    unbound or closed bundle raised past every ``except ValueError`` in the
    package -- including the emitter's abstention handler.  All four refusals
    are inside the boundary now.
    """

    evidence = _bundle()
    unbound = materialize_route_evidence(evidence)

    with pytest.raises(ValueError, match=REJECTION) as unbound_error:
        bundle_route_proof_refs(
            unbound, unbound.route_proofs, rejection=REJECTION,
        )
    assert type(unbound_error.value) is ValueError
    assert isinstance(unbound_error.value.__cause__, RuntimeJoinRejected)

    closed = _bundle()
    proofs = closed.route_proofs
    route_join_binding(closed).arena.close()

    with pytest.raises(ValueError, match=REJECTION) as closed_error:
        bundle_route_proof_refs(closed, proofs, rejection=REJECTION)
    assert type(closed_error.value) is ValueError
    assert isinstance(closed_error.value.__cause__, RuntimeJoinRejected)


def test_a_phase_owns_its_arenas_and_closes_them_on_the_production_path() -> None:
    """The arena has a lifecycle owner, so its closed branch is reachable.

    Without an owner the arena's lifetime is garbage collection, its
    fail-closed branch never runs outside tests, and every bundle holds a
    second strong reference set to its own proofs for as long as it lives.
    """

    with route_authority_phase("unit-test-production") as phase:
        evidence = _bundle()
        assert len(phase) == 1
        assert not phase.closed
        # The production join works while the phase that produced it is running.
        refs = bundle_route_proof_refs(
            evidence, evidence.route_proofs, rejection=REJECTION,
        )
        assert len(refs) == len(evidence.route_proofs)
        proofs = evidence.route_proofs

    assert phase.closed
    assert evidence.route_binding is not None
    assert not evidence.route_binding.is_live
    # ...and afterwards the same production call refuses, as a ValueError the
    # emitter's abstention handler catches.
    with pytest.raises(ValueError, match=REJECTION) as error:
        bundle_route_proof_refs(evidence, proofs, rejection=REJECTION)
    assert isinstance(error.value.__cause__, RuntimeJoinRejected)


def test_a_phase_closes_its_arenas_even_when_the_phase_raises() -> None:
    holder: list[CanonicalSemanticEvidence] = []

    with pytest.raises(RuntimeError, match="producer exploded"):
        with route_authority_phase("unit-test-raising"):
            holder.append(_bundle())
            raise RuntimeError("producer exploded")

    binding = holder[0].route_binding
    assert binding is not None and not binding.is_live


def test_a_bundle_produced_outside_a_phase_keeps_its_arena() -> None:
    """The phase owns exactly what it opened, never what it merely saw."""

    outside = _bundle()

    with route_authority_phase("unit-test-scope") as phase:
        inside = _bundle()
        assert len(phase) == 1

    assert not inside.route_binding.is_live
    assert outside.route_binding.is_live
    assert bundle_route_proof_refs(
        outside, outside.route_proofs, rejection=REJECTION,
    )


def test_a_phase_never_owns_an_arena_the_caller_opened() -> None:
    """A rebind hands the arena in; it does not hand ownership over.

    ``bind_route_evidence(evidence, arena=...)`` is the named rebind at the
    decode boundary and its caller already owns that arena.  Adopting it into
    whatever phase happens to be active would let the phase close an arena
    whose lifetime it knows nothing about -- a caller's cache, a longer-lived
    session -- so the rebind mints into it without taking it.
    """

    caller_owned = RuntimeAuthorityArena(
        runtime_semantic_route_scope(NATIVE_KEY, 7)
    )
    unbound = materialize_route_evidence(_bundle())

    with route_authority_phase("unit-test-rebind") as phase:
        rebound = bind_route_evidence(unbound, arena=caller_owned)
        # The phase minted nothing of its own, and it did not take the
        # caller's arena either.
        assert len(phase) == 0

    assert phase.closed
    assert not caller_owned.is_closed
    assert rebound.route_binding is not None
    assert rebound.route_binding.is_live
    assert bundle_route_proof_refs(
        rebound, rebound.route_proofs, rejection=REJECTION,
    )
    caller_owned.close()


def test_a_phase_still_owns_the_arenas_the_producer_factories_open() -> None:
    """Only the two arena-creating sites hand the arena to the active phase."""

    with route_authority_phase("unit-test-own") as phase:
        produced = _bundle()
        assert len(phase) == 1
        caller_owned = RuntimeAuthorityArena(
            runtime_semantic_route_scope(NATIVE_KEY, 9)
        )
        bind_route_evidence(materialize_route_evidence(produced), arena=caller_owned)
        assert len(phase) == 1

    assert not produced.route_binding.is_live
    assert not caller_owned.is_closed
    caller_owned.close()


def test_adopting_into_a_closed_phase_is_a_lifecycle_error_not_an_abstention() -> None:
    """The owner is wrong, not the records: this must not read as a join refusal.

    Every abstention handler in the pipeline is ``except (TypeError, ValueError)``.
    A ``RuntimeJoinRejected`` here -- it is a ``ValueError`` -- would turn
    "you reopened work under a phase you already ended" into a silent
    "produce no plan", which hides a lifecycle bug behind a normal decline.
    """

    phase = route_evidence.RouteAuthorityPhase("unit-test-closed")
    phase.close()
    arena = RuntimeAuthorityArena(runtime_semantic_route_scope(NATIVE_KEY, 11))

    with pytest.raises(RuntimeAuthorityArenaError, match="phase is closed") as adopted:
        phase.adopt(arena)
    assert not isinstance(adopted.value, ValueError)

    with pytest.raises(RuntimeAuthorityArenaError, match="cannot be made active"):
        with route_evidence.use_route_authority_phase(phase):
            pass  # pragma: no cover - the context manager refuses on entry
    arena.close()


def test_activating_an_owned_phase_never_closes_it() -> None:
    """The other half of the phase API: publish an owner, do not end it.

    A lifecycle session outlives every region of its own code that mints, so
    it needs activation without termination.  ``route_authority_phase`` is the
    create-and-end form; this is the publish-only form.
    """

    owner = route_evidence.RouteAuthorityPhase("unit-test-session-owner")

    with route_evidence.use_route_authority_phase(owner) as active:
        assert active is owner
        assert route_evidence.active_route_authority_phase() is owner
        evidence = _bundle()
        assert len(owner) == 1

    assert route_evidence.active_route_authority_phase() is None
    assert not owner.closed
    assert evidence.route_binding.is_live

    owner.close()
    assert not evidence.route_binding.is_live


def test_content_derived_id_validation_stays_content_keyed() -> None:
    """``_validate_content_derived_ids`` is the persistence guarantee.

    It must keep recomputing the sha256 of the bundle's own content and
    comparing it to the identity the bundle carries.  A reference-keyed
    version could not detect this: the references are correct and only the
    content identity is forged.
    """

    evidence = canonical_semantic_evidence_from_proofs(NATIVE_KEY, 3, (_proof(),))
    forged_group = "sha256:" + "0" * 64

    # It accepts exactly what the producer minted...
    route_evidence._validate_content_derived_ids(
        native_key=evidence.native_key,
        generation=evidence.generation,
        atomic_group_id=evidence.atomic_group_id,
        route_proofs=evidence.route_proofs,
    )
    # ...and refuses a group identity that is not the sha256 of the content.
    with pytest.raises(Exception, match="atomic group id is not content-derived"):
        route_evidence._validate_content_derived_ids(
            native_key=evidence.native_key,
            generation=evidence.generation,
            atomic_group_id=forged_group,
            route_proofs=evidence.route_proofs,
        )
    # A forged *proof* identity is refused for the same reason, and the
    # references of this bundle are correct throughout: only a content check
    # can see this.
    forged_proof = replace(
        evidence.route_proofs[0], proof_id="sha256:" + "1" * 64,
    )
    with pytest.raises(Exception, match="proof id is not content-derived"):
        route_evidence._validate_content_derived_ids(
            native_key=evidence.native_key,
            generation=evidence.generation,
            atomic_group_id=evidence.atomic_group_id,
            route_proofs=(forged_proof,),
        )


def test_scope_derived_id_validation_stays_rendered_identity_keyed() -> None:
    """``_validate_runtime_derived_ids`` checks the *rendering* against a scope.

    It asks whether the identities a bundle publishes are the ones its own
    scope minted, which is a question about strings by construction: the
    reference is the answer it is checking against, not the thing it compares.
    """

    scope = route_evidence.runtime_semantic_route_scope(NATIVE_KEY, 3)
    runtime = route_evidence.runtime_semantic_evidence_from_proofs(
        NATIVE_KEY, 3, (_proof(),), scope=scope,
    )
    identity = runtime.runtime_identity
    assert identity is not None

    route_evidence._validate_runtime_derived_ids(
        atomic_group_id=runtime.atomic_group_id,
        route_proofs=runtime.route_proofs,
        runtime_identity=identity,
    )
    with pytest.raises(Exception, match="atomic group id is not scope-derived"):
        route_evidence._validate_runtime_derived_ids(
            atomic_group_id=scope.identity(identity.proof_refs[0]),
            route_proofs=runtime.route_proofs,
            runtime_identity=identity,
        )
    with pytest.raises(Exception, match="proof ids are not scope-derived"):
        route_evidence._validate_runtime_derived_ids(
            atomic_group_id=runtime.atomic_group_id,
            route_proofs=(
                replace(runtime.route_proofs[0], proof_id="runtime:other#x"),
            ),
            runtime_identity=identity,
        )


def test_runtime_ingestion_dedup_stays_content_keyed() -> None:
    """``_runtime_authoritative_proofs`` is the runtime ingestion boundary.

    Like its canonical twin it runs before the successor bundle's identities
    exist, and its divergence check is explicitly about the *rendered* input
    id: the caller says which ids its own scope minted, and only those are
    held to it.  There is no reference to key any of that on.
    """

    scope = route_evidence.runtime_semantic_route_scope(NATIVE_KEY, 3)
    first = route_evidence.runtime_semantic_evidence_from_proofs(
        NATIVE_KEY, 3, (_proof(),), scope=scope,
    )
    owned = frozenset(item.proof_id for item in first.route_proofs)
    original = first.route_proofs[0]
    divergent = replace(
        original,
        source_anchor_ea=0x1400,
        source_identity=_identity(0x1400),
        delivery_region=NativeEaInterval(0x1400, 0x1401),
        state_write=replace(
            original.state_write,
            identity=_identity(0x1400),
            instruction_ea=0x1400,
            corridor_instruction_eas=(0x1400,),
        ),
    )

    # Outside the owned set the same rendered id is a string coincidence.
    assert len(
        route_evidence._runtime_authoritative_proofs(
            (first.route_proofs[0], divergent),
        )
    ) == 2
    # Inside it, it is corruption.
    with pytest.raises(Exception, match="divergent authoritative payload"):
        route_evidence._runtime_authoritative_proofs(
            (first.route_proofs[0], divergent), owned_route_ids=owned,
        )


# --------------------------------------------------------------------------
# The claim sidecar channel: a claim carries the references its bundle minted.
# --------------------------------------------------------------------------


def _route_claim_payload() -> tuple[object, object, dict[str, object]]:
    """Return one real producer claim type, its bundle refs, and its payload.

    The payload is the claim's canonical field values, so the two arms of
    every byte-identity test below are the *same content* built twice: once
    with the sidecar and once without.
    """

    source, proposal, _exclusion, _refs = exact_fixture()
    evidence = proposal.route_evidence
    proof = evidence.route_proofs[0]
    claim = producer_api.build_equivalent_route_claims(
        source=source,
        source_catalog=proposal.source_identity_catalog,
        route_evidence=evidence,
        selected_proof_ids=(proof.proof_id,),
    )[0]
    payload = {
        name: getattr(claim, name)
        for name in authority_ids._RECORD_FIELDS[type(claim)]
        if name != "claim_id"
    }
    return claim, route_join_binding(evidence).claim_refs(proof), payload


def test_the_claim_sidecar_is_written_before_the_record_seals(monkeypatch) -> None:
    """The lifecycle invariant: complete at ``__post_init__``, not after it.

    ``_claim_factory`` builds with ``object.__new__`` and per-field
    ``object.__setattr__``, so "attach the sidecar afterwards" would compile
    and would silently mutate an already-sealed record.  This observes the
    slot from inside the seal.
    """

    claim, sidecar, payload = _route_claim_payload()
    claim_type = type(claim)
    observed: list[object] = []
    original = claim_type.__post_init__

    def spy(self) -> None:
        observed.append(getattr(self, "_runtime_refs", "<unwritten>"))
        original(self)

    monkeypatch.setattr(claim_type, "__post_init__", spy)

    bound = authority_ids._claim_factory(
        claim_type, runtime_refs=sidecar, **payload,
    )
    unbound = authority_ids._claim_factory(claim_type, **payload)

    assert observed == [sidecar, None]
    assert bound.runtime_refs is sidecar
    assert unbound.runtime_refs is None


def test_a_claim_sidecar_naming_another_route_group_is_a_construction_error() -> None:
    """A mismatched sidecar is refused *while* the record seals.

    This is the behavioural half of the ordering test: the check lives in
    ``__post_init__``, so it can only fire if the sidecar was already written
    when the record sealed.  A factory that attached it later would accept
    this and produce a claim whose join authority names a different route.
    """

    claim, _sidecar, payload = _route_claim_payload()
    foreign_bundle = _bundle()
    foreign = route_join_binding(foreign_bundle).claim_refs(
        foreign_bundle.route_proofs[0],
    )

    assert foreign.atomic_group_id != claim.atomic_group_id

    with pytest.raises(ValueError, match="runtime refs name another route group"):
        authority_ids._claim_factory(
            type(claim), runtime_refs=foreign, **payload,
        )


def test_the_claim_sidecar_moves_no_canonical_byte_and_no_content_id() -> None:
    """Content and authority stay separate: same bytes, same IDs, same value."""

    claim, sidecar, payload = _route_claim_payload()
    claim_type = type(claim)

    bound = authority_ids._claim_factory(
        claim_type, runtime_refs=sidecar, **payload,
    )
    unbound = authority_ids._claim_factory(claim_type, **payload)

    assert bound.runtime_refs is sidecar
    assert unbound.runtime_refs is None
    assert bound == unbound
    assert bound.claim_id == unbound.claim_id == claim.claim_id
    assert authority_ids.claim_id(bound) == authority_ids.claim_id(unbound)
    assert authority_ids.canonical_bytes(bound) == authority_ids.canonical_bytes(
        unbound
    )
    # ... and inside a container, which is how a claim actually reaches a seal.
    assert authority_ids.canonical_bytes(
        (bound, unbound)
    ) == authority_ids.canonical_bytes((unbound, unbound))
    assert authority_ids.canonical_bytes(bound) == authority_ids.canonical_bytes(
        claim
    )


def test_a_persisted_claim_decodes_unbound() -> None:
    """Persistence materializes content; a decoded claim has no authority."""

    claim, sidecar, payload = _route_claim_payload()
    bound = authority_ids._claim_factory(
        type(claim), runtime_refs=sidecar, **payload,
    )

    decoded = authority_ids.canonical_decode(authority_ids.canonical_bytes(bound))

    assert decoded == bound
    assert decoded.runtime_refs is None
    assert authority_ids.validate_canonical_roundtrip(bound, type(claim)) == bound


def test_a_deep_copy_of_a_bound_claim_is_unbound() -> None:
    """A copy is a value, not an authority -- the bundle's rule, for claims."""

    claim, sidecar, payload = _route_claim_payload()
    bound = authority_ids._claim_factory(
        type(claim), runtime_refs=sidecar, **payload,
    )

    clone = copy.deepcopy(bound)

    assert clone == bound
    assert clone.runtime_refs is None


def test_registry_snapshot_and_detached_copy_ignore_the_claim_sidecar() -> None:
    """The seal covers the canonical schema; the sidecar is not in it."""

    claim, sidecar, payload = _route_claim_payload()
    claim_type = type(claim)
    bound = authority_ids._claim_factory(
        claim_type, runtime_refs=sidecar, **payload,
    )
    unbound = authority_ids._claim_factory(claim_type, **payload)

    assert bind._registry_structural_snapshot(
        bound
    ) == bind._registry_structural_snapshot(unbound)

    detached = bind._detached_canonical_copy(bound, {})

    assert type(detached) is claim_type
    assert detached.runtime_refs is None
    assert detached == bound
    # The detached copy leaves the slot *unwritten*, which is the record shape
    # every reader of the sidecar must tolerate.
    claim_type.__post_init__(detached)


def test_the_sidecar_channel_refuses_a_claim_type_that_declares_no_slot() -> None:
    """Only a record that declares the sidecar may be handed one."""

    _claim, sidecar, _payload = _route_claim_payload()

    with pytest.raises(TypeError, match="claim record that declares one"):
        authority_ids._claim_factory(
            model.ExactInfeasibleEffectClaim, runtime_refs=sidecar,
        )


# --------------------------------------------------------------------------
# The claim family joins on those references instead of on the content ID.
# --------------------------------------------------------------------------


def test_the_producer_mints_every_route_claim_carrying_its_bundle_references() -> None:
    """The claim leaves the factory bound, and its canonical bytes do not move."""


    source, proposal, _exclusion, _refs = exact_fixture()
    evidence = proposal.route_evidence
    proof = evidence.route_proofs[0]
    binding = route_join_binding(evidence)

    claim = producer_api.build_equivalent_route_claims(
        source=source,
        source_catalog=proposal.source_identity_catalog,
        route_evidence=evidence,
        selected_proof_ids=(proof.proof_id,),
    )[0]

    refs = producer_api.route_claim_join_refs(claim)
    assert refs.proof_refs == (binding.ref_for(proof),)
    assert refs.group_ref is binding.group_ref
    assert refs.atomic_group_id == claim.atomic_group_id
    # The fingerprint is untouched: the same claim built without a sidecar is
    # the same value, the same ID and the same bytes.
    payload = {
        name: getattr(claim, name)
        for name in authority_ids._RECORD_FIELDS[type(claim)]
        if name != "claim_id"
    }
    unbound = authority_ids._claim_factory(type(claim), **payload)
    assert unbound == claim
    assert unbound.claim_id == claim.claim_id
    assert authority_ids.canonical_bytes(unbound) == authority_ids.canonical_bytes(
        claim
    )


def test_the_route_claim_correspondence_refuses_a_content_equal_foreign_claim() -> None:
    """Two bundles, identical content: only the arena can tell the claims apart.

    ``resolve_equivalent_route_claim`` used to select the rebuilt claim whose
    ``claim_id`` matched, which asks whether *some* claim with these bytes was
    rebuilt.  The authority question is whether this claim is about this
    proposal's route, and a claim minted from another bundle answers it "no"
    even though every canonical byte agrees.
    """

    source, proposal, _exclusion, refs = exact_fixture()
    other_source, other_proposal, _other_exclusion, _other_refs = exact_fixture()
    proof = proposal.route_evidence.route_proofs[0]
    other_proof = other_proposal.route_evidence.route_proofs[0]

    def claims_for(graph, contract, selected):
        return producer_api.build_equivalent_route_claims(
            source=graph,
            source_catalog=contract.source_identity_catalog,
            route_evidence=contract.route_evidence,
            selected_proof_ids=(selected.proof_id,),
        )[0]

    own = claims_for(source, proposal, proof)
    foreign = claims_for(other_source, other_proposal, other_proof)

    # Content cannot distinguish them.
    assert foreign == own
    assert foreign.claim_id == own.claim_id
    assert authority_ids.canonical_bytes(foreign) == authority_ids.canonical_bytes(own)
    # Authority can.
    assert producer_api.route_claim_join_refs(
        foreign
    ) != producer_api.route_claim_join_refs(own)

    def proposal_with(claim):
        return replace(
            proposal,
            claims=(claim,),
            plan_inputs=replace(
                proposal.plan_inputs,
                shape=model.UnflattenPlanShape.PARTIAL_REWRITE,
            ),
        )

    assert producer_api.resolve_equivalent_route_claim(
        source=source,
        proposal=proposal_with(own),
        claim=own,
        block_refs_by_serial=refs,
    ) is own

    with pytest.raises(ValueError, match="route claim is stale or ambiguous"):
        producer_api.resolve_equivalent_route_claim(
            source=source,
            proposal=proposal_with(foreign),
            claim=foreign,
            block_refs_by_serial=refs,
        )


def test_an_unbound_claim_is_refused_at_the_claim_join() -> None:
    """A decoded claim carries a fingerprint and no authority; the join says so."""



    source, proposal, _exclusion, refs = exact_fixture()
    proof = proposal.route_evidence.route_proofs[0]
    claim = producer_api.build_equivalent_route_claims(
        source=source,
        source_catalog=proposal.source_identity_catalog,
        route_evidence=proposal.route_evidence,
        selected_proof_ids=(proof.proof_id,),
    )[0]
    decoded = authority_ids.canonical_decode(authority_ids.canonical_bytes(claim))

    assert decoded == claim
    with pytest.raises(RuntimeJoinRejected, match="not bound to a runtime"):
        producer_api.route_claim_join_refs(decoded)

    route_proposal = replace(
        proposal,
        claims=(decoded,),
        plan_inputs=replace(
            proposal.plan_inputs,
            shape=model.UnflattenPlanShape.PARTIAL_REWRITE,
        ),
    )

    with pytest.raises(ValueError, match="route claim is stale or ambiguous") as error:
        producer_api.resolve_equivalent_route_claim(
            source=source,
            proposal=route_proposal,
            claim=decoded,
            block_refs_by_serial=refs,
        )
    assert isinstance(error.value.__cause__, RuntimeJoinRejected)


def test_a_claim_that_outlives_its_phase_can_no_longer_be_joined() -> None:
    """Why the transaction-side claim joins are not converted in this task.

    A claim minted inside the emission carries references into a plan that
    outlives it.  The phase closes the arena on the way out, so the *join* is
    refused afterwards while the content stays perfectly readable -- which is
    exactly why the transaction needs its own arena before its claim joins can
    be reference-keyed.
    """

    with route_authority_phase("test-emission"):
        source, proposal, _exclusion, _refs = exact_fixture()
        proof = proposal.route_evidence.route_proofs[0]
        claim = producer_api.build_equivalent_route_claims(
            source=source,
            source_catalog=proposal.source_identity_catalog,
            route_evidence=proposal.route_evidence,
            selected_proof_ids=(proof.proof_id,),
        )[0]
        assert producer_api.route_claim_join_refs(claim).is_live

    assert claim.runtime_refs is not None
    assert not claim.runtime_refs.is_live
    with pytest.raises(RuntimeJoinRejected, match="closed"):
        producer_api.route_claim_join_refs(claim)
    # The content is untouched by the phase ending.
    assert authority_ids.claim_id(claim) == claim.claim_id


def _case_with_a_route_claim() -> object:
    """Build one real safety case whose claims include a route claim."""

    phase = model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
    entry = _role_subject(model.SemanticSubjectRole.SOURCE_ENTRY, "walker-pin")
    catalog = tuple(
        _role_subject(model.SemanticSubjectRole.SOURCE_CATALOG_BLOCK, str(index))
        for index in range(3)
    )
    inputs = _with_entry_gate_facts(
        _complete_inputs(source_subjects=(entry, *catalog), phase=phase),
        passed=True,
        reason="",
    )
    return build_semantic_case(
        authority_id=authority_ids.authority_id("claim-walker-pin-case"),
        phase=phase,
        inputs=inputs,
    )


def test_the_generic_model_walkers_tolerate_a_detached_claim() -> None:
    """The record shape a detached canonical copy produces must stay walkable.

    ``bind._detached_canonical_copy`` rebuilds a record field by field and
    deliberately leaves the sidecar slot **unwritten** -- not ``None``,
    absent.  Two ``model`` walkers enumerate ``dataclasses.fields`` and read
    each name with a bare ``getattr``, so adding the sidecar made them raise
    ``AttributeError`` on exactly that shape.  Both are pinned here: with
    either private-name skip removed, this test fails with

        AttributeError: 'EquivalentSemanticRouteClaim' object has no
        attribute '_runtime_refs'
    """

    case = _case_with_a_route_claim()
    claim = next(
        item for item in case.claims
        if type(item) is model.EquivalentSemanticRouteClaim
    )
    detached = bind._detached_canonical_copy(claim, {})

    # The shape itself: the slot is absent, not None.
    with pytest.raises(AttributeError):
        object.__getattribute__(detached, "_runtime_refs")
    assert detached.runtime_refs is None
    assert detached == claim

    # Walker 1: model._claim_subjects.
    assert model._claim_subjects(detached) == model._claim_subjects(claim)

    # Walker 2: the safety case's occurrence revalidation, reached the way
    # production reaches it -- by revalidating a case that carries the record.
    rebuilt = replace(case, claims=(detached,))

    assert rebuilt.claims[0] == claim
