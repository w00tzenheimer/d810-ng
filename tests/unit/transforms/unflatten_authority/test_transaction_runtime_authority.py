"""The producer/transaction seam is a rebind, never an adoption.

The producer's arena is owned by the emission and is already closed when the
authority transaction reads the plan.  These tests pin that the transaction
opens its *own* arena, that the seam verifies the producer's claims before
minting, that nothing joins without passing through the seam, and that a
refusal at the seam abstains through the transaction's existing ``ValueError``
boundary instead of escaping.
"""

from __future__ import annotations

import ast
import logging
from dataclasses import fields, replace
from pathlib import Path

import pytest

from d810.analyses.control_flow.semantic_route_evidence import (
    CanonicalSemanticEvidence,
    SemanticRouteEvidenceRejected,
    SemanticRouteDestination,
    SemanticRouteProof,
    SemanticRouteProofKind,
    SemanticRouteShape,
    SemanticStateWriteProof,
    canonical_semantic_evidence_from_proofs,
    materialize_route_evidence,
    rebind_route_authority,
    RouteRebindVerification,
    route_authority_phase,
    route_join_binding,
    runtime_semantic_evidence_from_proofs,
    runtime_semantic_route_scope,
)
from d810.core import logging as d810_logging
from d810.core.runtime_identity import (
    RUNTIME_AUTHORITY_SIDECAR_FIELDS,
    RUNTIME_SUBJECT_SIDECAR_FIELD,
    RUNTIME_VERDICT_SIDECAR_FIELD,
    RuntimeAuthorityArena,
    RuntimeAuthorityKind,
    RuntimeJoinRejected,
)
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.transforms.unflatten_authority.canonical_session import (
    CanonicalSessionPhase,
    CanonicalValidationSession,
    _canonical_validation_session,
    active_canonical_session,
)
from d810.transforms.unflatten_authority import bind
from d810.transforms.unflatten_authority import ids as authority_ids
from d810.transforms.unflatten_authority import legacy_codec
from d810.transforms.unflatten_authority.runtime_authority import (
    TransactionSubjectRecord,
    rebind_route_evidence,
    subject_join_ref,
    transaction_authority_session,
    transaction_route_arena,
    transaction_route_binding,
    transaction_route_verification,
    transaction_subject_ref,
)
from d810.analyses.control_flow.graph_checks import (
    check_effectful_reachability_preserved,
    check_entry_reachability_not_collapsed,
    check_terminal_reachability_preserved,
)
from d810.transforms.cfg_transaction import CfgProjection, PlanBlockRef
from d810.transforms.unflatten_authority import model, transaction_api
from d810.transforms.unflatten_authority.gates import GenericCfgGateBundle
from tests.native_preanalysis import make_native_key

from . import test_bind

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


def _emitted_bundle() -> CanonicalSemanticEvidence:
    """A bundle produced the way production produces one: inside a phase that ends."""

    with route_authority_phase("test-emission"):
        evidence = _bundle()
    assert not evidence.route_binding.is_live
    return evidence


def test_the_session_owns_one_arena_and_closes_it_with_itself() -> None:
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION,
    ) as session:
        arena = transaction_route_arena()
        assert arena is session.route_arena
        assert not arena.is_closed
        assert transaction_authority_session() is session

    assert session.closed
    assert arena.is_closed


def test_the_two_transaction_phases_own_two_arenas_that_share_no_reference() -> None:
    """A projected ordinal must never be readable as an observed one."""

    evidence = _emitted_bundle()

    with _canonical_validation_session(CanonicalSessionPhase.PROJECTED_PREPARATION):
        projected = rebind_route_evidence(evidence).binding
        projected_refs = projected.proof_refs
    with _canonical_validation_session(CanonicalSessionPhase.OBSERVED_REVALIDATION):
        observed = rebind_route_evidence(evidence).binding

        assert observed is not projected
        assert observed.proof_refs != projected_refs
        with pytest.raises(RuntimeJoinRejected):
            observed.order_key(projected_refs[0])


def test_a_join_outside_a_transaction_session_has_no_owner_and_is_refused() -> None:
    evidence = _emitted_bundle()

    with pytest.raises(RuntimeJoinRejected, match="requires an active canonical"):
        transaction_route_binding(evidence)
    with pytest.raises(RuntimeJoinRejected, match="requires an active canonical"):
        rebind_route_evidence(evidence)


def test_a_bundle_that_never_passed_the_seam_cannot_be_joined() -> None:
    """No implicit adoption: the transaction acquires authority by asking for it."""

    evidence = _emitted_bundle()

    with _canonical_validation_session(CanonicalSessionPhase.PROJECTED_PREPARATION):
        with pytest.raises(RuntimeJoinRejected, match="was not rebound into this"):
            transaction_route_binding(evidence)

        binding = rebind_route_evidence(evidence).binding

        assert transaction_route_binding(evidence) is binding
        assert binding.ref_for(evidence.route_proofs[0]) is binding.proof_refs[0]
        assert all(
            ref.kind is RuntimeAuthorityKind.ROUTE_PROOF for ref in binding.proof_refs
        )


def test_the_seam_is_idempotent_for_one_occurrence_in_one_session() -> None:
    """Every read of ``proposal.route_evidence`` must reach one authority."""

    evidence = _emitted_bundle()

    with _canonical_validation_session(CanonicalSessionPhase.PROJECTED_PREPARATION):
        first = rebind_route_evidence(evidence)
        second = rebind_route_evidence(evidence)

        assert first is second
        assert len(first.binding.proof_refs) == len(evidence.route_proofs)


def test_the_seam_never_adopts_the_producer_arena() -> None:
    """The transaction's session must not end another scope's arena."""

    with route_authority_phase("test-emission") as phase:
        evidence = _bundle()
        producer_arena = evidence.route_binding.arena
        assert not producer_arena.is_closed

        with _canonical_validation_session(
            CanonicalSessionPhase.PROJECTED_PREPARATION,
        ) as session:
            rebind_route_evidence(evidence)
            assert session.route_arena is not producer_arena
            assert len(phase) == 1

        # The transaction session ended; the producer's arena is untouched.
        assert not producer_arena.is_closed
        assert route_join_binding(evidence).is_live

    assert phase.closed
    assert producer_arena.is_closed


def test_a_bundle_cannot_carry_a_binding_minted_for_other_proofs() -> None:
    """Why the seam does not re-check fingerprints: the shape is unconstructible.

    A guard whose branch cannot be reached is not a safety net, so this is the
    measurement that keeps one out of ``rebind_route_authority``.  Forging a
    bundle whose binding names other proofs raises out of the *bundle's own*
    validator, on both identity disciplines: content-derived IDs are
    re-derived from the proofs, scope-derived IDs must come from the scope.
    """

    content_derived = _emitted_bundle()
    with pytest.raises(
        SemanticRouteEvidenceRejected, match="proof id is not content-derived"
    ):
        replace(
            content_derived,
            route_proofs=(
                replace(content_derived.route_proofs[0], proof_id="sha256:" + "e" * 64),
                content_derived.route_proofs[1],
            ),
        )

    scope = runtime_semantic_route_scope(NATIVE_KEY, 3)
    scope_derived = runtime_semantic_evidence_from_proofs(
        NATIVE_KEY, 3, (_proof(), _proof(0x1400, 0x11223344)), scope=scope,
    )
    foreign = scope.identity(scope.mint(RuntimeAuthorityKind.ROUTE_PROOF))
    with pytest.raises(
        SemanticRouteEvidenceRejected, match="proof ids are not scope-derived"
    ):
        replace(
            scope_derived,
            route_proofs=(
                replace(scope_derived.route_proofs[0], proof_id=foreign),
                scope_derived.route_proofs[1],
            ),
        )


def test_the_seam_verifies_the_producer_records_while_that_arena_is_open() -> None:
    """The check with real reach: a copy is content-equal and a different record.

    ``replace`` on a bundle passes every content invariant -- the proofs
    re-derive to the same IDs -- and carries the producer's binding with it,
    so nothing upstream notices that the proofs are now different objects.
    Binding them as the producer's would give one route two authorities.
    """

    evidence = _bundle()
    swapped = replace(
        evidence,
        route_proofs=tuple(replace(proof) for proof in evidence.route_proofs),
    )
    assert swapped.route_binding is evidence.route_binding
    assert swapped == evidence
    assert swapped.route_proofs[0] is not evidence.route_proofs[0]

    with _canonical_validation_session(CanonicalSessionPhase.PROJECTED_PREPARATION):
        with pytest.raises(RuntimeJoinRejected, match="another route proof record"):
            rebind_route_evidence(swapped)


def test_an_unbound_bundle_is_what_the_seam_exists_to_bind() -> None:
    """A decoded bundle carries a fingerprint and no authority; the seam gives one."""

    unbound = materialize_route_evidence(_emitted_bundle())
    assert unbound.route_binding is None

    with _canonical_validation_session(CanonicalSessionPhase.PROJECTED_PREPARATION):
        rebind = rebind_route_evidence(unbound)
        binding = rebind.binding

        assert rebind.verification is RouteRebindVerification.PRODUCER_UNBOUND
        assert not rebind.records_verified
        assert binding.is_live
        assert binding.atomic_group_id == unbound.atomic_group_id
        assert len(binding.proof_refs) == len(unbound.route_proofs)
        assert binding.ref_for(unbound.route_proofs[0]) is binding.proof_refs[0]


def test_the_seam_moves_no_canonical_byte_and_mints_no_content_id() -> None:
    """The record crossing the seam is unchanged; only the scope's view of it is new."""

    evidence = _emitted_bundle()
    before_group = evidence.atomic_group_id
    before_ids = tuple(proof.proof_id for proof in evidence.route_proofs)

    with _canonical_validation_session(CanonicalSessionPhase.PROJECTED_PREPARATION):
        rebound = rebind_route_evidence(evidence).binding

        assert evidence.atomic_group_id == before_group
        assert tuple(proof.proof_id for proof in evidence.route_proofs) == before_ids
        assert rebound.atomic_group_id == before_group
        # The producer's binding is still the producer's.
        assert evidence.route_binding is not rebound
        assert evidence.route_binding.arena is not rebound.arena


def test_the_binding_dies_with_the_session_that_minted_it() -> None:
    evidence = _emitted_bundle()

    with _canonical_validation_session(CanonicalSessionPhase.PROJECTED_PREPARATION):
        binding = rebind_route_evidence(evidence).binding
        assert binding.is_live

    assert not binding.is_live
    with pytest.raises(RuntimeJoinRejected):
        binding.ref_for(evidence.route_proofs[0])


def test_rebinding_into_a_closed_arena_is_refused() -> None:
    evidence = _emitted_bundle()
    arena = RuntimeAuthorityArena(runtime_semantic_route_scope(NATIVE_KEY, 5))
    arena.close()

    with pytest.raises(RuntimeJoinRejected, match="closed runtime authority arena"):
        rebind_route_authority(evidence, arena=arena)


def test_a_closed_session_owns_no_authority() -> None:
    session = CanonicalValidationSession(CanonicalSessionPhase.OBSERVED_REVALIDATION)
    session._close()

    with pytest.raises(RuntimeError, match="session is closed"):
        session.route_arena
    with pytest.raises(RuntimeError, match="session is closed"):
        session.runtime_binding_for(object())


def test_a_refused_rebind_rejects_the_transaction_instead_of_escaping(
    monkeypatch,
) -> None:
    """The seam abstains through the transaction's own ``ValueError`` boundary.

    This is the transaction-side twin of the emitter proof in 5b: a refusal at
    a runtime join must decline a plan, never abort a decompilation.  The
    preparation is run twice on one real fixture -- first accepting, so the
    seam is proved to be *reached* on the production path, then with the seam
    refusing -- and the second run must return a rejected verdict.
    """

    values = test_bind._compiler_guarded_convert_to_goto_case(include_graphs=True)
    plan, attempt, source, projected = values[1], values[5], values[6], values[7]
    raw_effect = check_effectful_reachability_preserved(source, post_cfg=projected)
    gates = GenericCfgGateBundle(
        check_entry_reachability_not_collapsed(source, post_cfg=projected),
        raw_effect,
        raw_effect,
        check_terminal_reachability_preserved(source, post_cfg=projected),
    )
    arguments = {
        "source": source,
        "projection": CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        "plan": plan,
        "attempt_id": attempt,
        "generic_gates": gates,
    }

    reached: list[CanonicalSemanticEvidence] = []
    real_rebind = transaction_api.rebind_route_evidence

    def _observed(evidence: CanonicalSemanticEvidence):
        reached.append(evidence)
        return real_rebind(evidence)

    monkeypatch.setattr(transaction_api, "rebind_route_evidence", _observed)
    accepted = transaction_api.prepare_unflatten_authority(**arguments)

    assert type(accepted) is model.UnflattenAuthorityPreparationAccepted
    assert reached == [plan.unflatten_proposal.route_evidence]

    def _refused(evidence: CanonicalSemanticEvidence):
        raise RuntimeJoinRejected("the seam refuses this bundle")

    monkeypatch.setattr(transaction_api, "rebind_route_evidence", _refused)
    rejected = transaction_api.prepare_unflatten_authority(**arguments)

    assert type(rejected) is model.UnflattenAuthorityPreparationRejected
    assert not rejected.verdict.accepted
    assert (
        rejected.verdict.reason
        is model.UnflattenAuthorityReason.PROJECTED_BINDING_FAILED
    )
    assert isinstance(RuntimeJoinRejected("x"), ValueError)


def _subject(block_ref: PlanBlockRef, anchor_ea: int):
    return authority_ids._subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.PLANNED_HELPER,
        block_ref=block_ref,
        anchor_ea=anchor_ea,
        locator=model.BlockSubjectLocator(block_ref, anchor_ea),
    )


SUBJECT_REF = PlanBlockRef("sha256:" + "1" * 64, "helper")


def test_a_subject_minted_in_a_transaction_carries_that_transactions_reference() -> None:
    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION,
    ) as session:
        subject = _subject(SUBJECT_REF, 0x1200)

        ref = subject_join_ref(subject)

        assert ref is subject.runtime_ref
        assert ref.kind is RuntimeAuthorityKind.SUBJECT
        assert session.route_arena.owns(ref)
        assert session.route_arena.get(ref).subject_id == subject.subject_id


def test_the_same_subject_reconstructed_in_one_session_gets_one_reference() -> None:
    """A subject is rebuilt from several sources; all of them are one subject.

    The transaction constructs the same semantic subject from an inventory,
    from a claim member and from a catalog witness.  Minting per construction
    would make one subject three unequal authorities, which is not a stricter
    join but a broken one, so the mint is interned on the canonical id.
    """

    with _canonical_validation_session(CanonicalSessionPhase.PROJECTED_PREPARATION):
        first = _subject(SUBJECT_REF, 0x1200)
        second = _subject(SUBJECT_REF, 0x1200)
        other = _subject(PlanBlockRef("sha256:" + "1" * 64, "other"), 0x1300)

        assert first is not second
        assert first.subject_id == second.subject_id
        assert subject_join_ref(first) is subject_join_ref(second)
        assert subject_join_ref(other) is not subject_join_ref(first)


def test_a_producer_built_subject_is_unbound_and_refused_at_a_join() -> None:
    """The emission builds subjects with no session; they carry no authority."""

    from_producer = _subject(SUBJECT_REF, 0x1200)

    assert from_producer.runtime_ref is None

    with _canonical_validation_session(CanonicalSessionPhase.PROJECTED_PREPARATION):
        with pytest.raises(RuntimeJoinRejected, match="was not minted by this"):
            subject_join_ref(from_producer)


def test_a_subject_minted_by_another_session_is_refused() -> None:
    with _canonical_validation_session(CanonicalSessionPhase.PROJECTED_PREPARATION):
        projected = _subject(SUBJECT_REF, 0x1200)
        assert subject_join_ref(projected) is projected.runtime_ref

    with _canonical_validation_session(CanonicalSessionPhase.OBSERVED_REVALIDATION):
        observed = _subject(SUBJECT_REF, 0x1200)

        assert observed == projected
        assert observed.runtime_ref is not projected.runtime_ref
        with pytest.raises(RuntimeJoinRejected, match="another transaction session"):
            subject_join_ref(projected)


def test_the_subject_sidecar_is_written_before_the_record_seals(monkeypatch) -> None:
    """The lifecycle invariant, observed from inside the seal."""

    observed: list[object] = []
    original = model.SemanticSubjectRef.__post_init__

    def spy(self) -> None:
        observed.append(getattr(self, "_runtime_ref", "<unwritten>"))
        original(self)

    monkeypatch.setattr(model.SemanticSubjectRef, "__post_init__", spy)

    with _canonical_validation_session(CanonicalSessionPhase.PROJECTED_PREPARATION):
        bound = _subject(SUBJECT_REF, 0x1200)
    unbound = _subject(SUBJECT_REF, 0x1200)

    assert observed == [bound.runtime_ref, None]
    assert observed[0] is not None


def test_a_subject_sidecar_of_the_wrong_kind_is_a_construction_error() -> None:
    """The behavioural half: the check can only fire from inside the seal."""

    with _canonical_validation_session(
        CanonicalSessionPhase.PROJECTED_PREPARATION,
    ) as session:
        foreign = session.route_arena.mint(
            RuntimeAuthorityKind.CLAIM, TransactionSubjectRecord("sha256:" + "0" * 64),
        )
        with pytest.raises(TypeError, match="must be a subject reference"):
            model.SemanticSubjectRef(
                kind=model.SemanticSubjectKind.BLOCK,
                role=model.SemanticSubjectRole.PLANNED_HELPER,
                subject_id=authority_ids.subject_id(
                    model.SemanticSubjectKind.BLOCK,
                    model.SemanticSubjectRole.PLANNED_HELPER,
                    model.BlockSubjectLocator(SUBJECT_REF, 0x1200),
                ),
                block_ref=SUBJECT_REF,
                anchor_ea=0x1200,
                locator=model.BlockSubjectLocator(SUBJECT_REF, 0x1200),
                _runtime_ref=foreign,
            )


def test_the_subject_sidecar_moves_no_canonical_byte_and_no_content_id() -> None:
    """Content and authority stay separate: same bytes, same ID, same value."""

    with _canonical_validation_session(CanonicalSessionPhase.PROJECTED_PREPARATION):
        bound = _subject(SUBJECT_REF, 0x1200)
    unbound = _subject(SUBJECT_REF, 0x1200)

    assert bound.runtime_ref is not None
    assert unbound.runtime_ref is None
    assert bound == unbound
    assert bound.subject_id == unbound.subject_id
    assert authority_ids.canonical_bytes(bound) == authority_ids.canonical_bytes(
        unbound
    )
    assert authority_ids.canonical_bytes(
        (bound, unbound)
    ) == authority_ids.canonical_bytes((unbound, unbound))
    assert "_runtime_ref" not in repr(bound)


def test_a_persisted_subject_decodes_unbound() -> None:
    with _canonical_validation_session(CanonicalSessionPhase.PROJECTED_PREPARATION):
        bound = _subject(SUBJECT_REF, 0x1200)

        decoded = authority_ids.canonical_decode(authority_ids.canonical_bytes(bound))

        assert decoded == bound
        assert decoded.runtime_ref is None
        assert (
            authority_ids.validate_canonical_roundtrip(
                bound, model.SemanticSubjectRef,
            )
            == bound
        )


def test_the_subject_sidecar_is_in_the_closed_set_and_outside_the_schema() -> None:
    assert RUNTIME_SUBJECT_SIDECAR_FIELD in RUNTIME_AUTHORITY_SIDECAR_FIELDS
    assert RUNTIME_SUBJECT_SIDECAR_FIELD == "_runtime_ref"
    assert RUNTIME_SUBJECT_SIDECAR_FIELD not in authority_ids._RECORD_FIELDS[
        model.SemanticSubjectRef
    ]
    assert all(
        field.compare is False and field.repr is False
        for field in fields(model.SemanticSubjectRef)
        if field.name == RUNTIME_SUBJECT_SIDECAR_FIELD
    )


def test_the_generic_walkers_tolerate_a_detached_subject() -> None:
    """A detached copy leaves the slot *unwritten*, not ``None``.

    ``_detached_canonical_copy`` rebuilds a record from its canonical schema
    only, so on a ``slots=True`` record the sidecar slot does not exist at
    all.  Every reader must therefore go through the property, which reads it
    with a default; a bare ``getattr`` would raise on exactly the shape
    detaching produces.
    """

    with _canonical_validation_session(CanonicalSessionPhase.PROJECTED_PREPARATION):
        bound = _subject(SUBJECT_REF, 0x1200)

    detached = bind._detached_canonical_copy(bound, {})

    with pytest.raises(AttributeError):
        object.__getattribute__(detached, RUNTIME_SUBJECT_SIDECAR_FIELD)
    assert detached.runtime_ref is None
    assert detached == bound
    assert authority_ids.canonical_bytes(detached) == authority_ids.canonical_bytes(
        bound
    )
    assert bind._registry_structural_snapshot(
        detached
    ) == bind._registry_structural_snapshot(bound)


def test_the_seam_names_what_it_could_verify_on_each_producer_path() -> None:
    """The seam's substantive check is conditional; the condition is recorded.

    Which of the three outcomes a transaction gets depends on the producer
    path, and two of them occur in production:

    * a bundle carried unchanged from the lifecycle session that projected it
      keeps a **live** arena at the seam -- that session's phase is released at
      top-level session completion, after the transaction;
    * a bundle **reminted inside the unflatten emission** carries an arena the
      emission phase closed on its way out, so record identity cannot be
      checked here;
    * a decoded bundle carries no binding at all.

    None of the three is a fault, and none of them may be a silent branch.
    """

    session_owned = _bundle()  # arena still open, as the session provider's is
    reminted_in_emission = _emitted_bundle()
    decoded = materialize_route_evidence(_emitted_bundle())

    with _canonical_validation_session(CanonicalSessionPhase.PROJECTED_PREPARATION):
        assert (
            rebind_route_evidence(session_owned).verification
            is RouteRebindVerification.PRODUCER_RECORDS_VERIFIED
        )
        assert (
            rebind_route_evidence(reminted_in_emission).verification
            is RouteRebindVerification.PRODUCER_ARENA_CLOSED
        )
        assert (
            rebind_route_evidence(decoded).verification
            is RouteRebindVerification.PRODUCER_UNBOUND
        )

        # ...and every one of them is readable afterwards, from the session,
        # rather than being consumed at the branch that decided it.
        assert transaction_route_verification(session_owned).value == (
            "producer-records-verified"
        )
        assert transaction_route_verification(reminted_in_emission).value == (
            "producer-arena-closed"
        )
        assert transaction_route_verification(decoded).value == "producer-unbound"
        assert rebind_route_evidence(session_owned).records_verified
        assert not rebind_route_evidence(decoded).records_verified


def test_the_verification_outcome_needs_the_seam_to_have_run() -> None:
    """It is a recorded fact about a rebind, not a property computed on demand."""

    evidence = _emitted_bundle()

    with _canonical_validation_session(CanonicalSessionPhase.PROJECTED_PREPARATION):
        with pytest.raises(RuntimeJoinRejected, match="was not rebound into this"):
            transaction_route_verification(evidence)

        rebind_route_evidence(evidence)

        assert (
            transaction_route_verification(evidence)
            is RouteRebindVerification.PRODUCER_ARENA_CLOSED
        )


def test_a_live_producer_binding_still_fails_closed_on_a_foreign_record() -> None:
    """Making the outcome explicit did not soften the check that can run."""

    evidence = _bundle()
    swapped = replace(
        evidence,
        route_proofs=tuple(replace(proof) for proof in evidence.route_proofs),
    )

    with _canonical_validation_session(CanonicalSessionPhase.PROJECTED_PREPARATION):
        with pytest.raises(RuntimeJoinRejected, match="another route proof record"):
            rebind_route_evidence(swapped)


def test_a_decoded_subject_stays_unbound_inside_an_active_session() -> None:
    """Decoding produces unbound values; a live session must not adopt them.

    A subject rebuilt from a persisted payload has no runtime authority to
    inherit.  Interning would have handed it the *same* reference as a live
    subject of equal content merely because a session happened to be open,
    which is the implicit adoption the binding design forbids.
    """

    with _canonical_validation_session(CanonicalSessionPhase.PROJECTED_PREPARATION):
        live = _subject(SUBJECT_REF, 0x1200)
        from_payload = authority_ids._subject_factory(
            model.SemanticSubjectRef,
            decoded=True,
            kind=model.SemanticSubjectKind.BLOCK,
            role=model.SemanticSubjectRole.PLANNED_HELPER,
            block_ref=SUBJECT_REF,
            anchor_ea=0x1200,
            locator=model.BlockSubjectLocator(SUBJECT_REF, 0x1200),
        )

        assert from_payload == live
        assert from_payload.subject_id == live.subject_id
        assert from_payload.runtime_ref is None
        assert live.runtime_ref is not None
        with pytest.raises(RuntimeJoinRejected, match="was not minted by this"):
            subject_join_ref(from_payload)


def test_every_legacy_decode_site_marks_its_subjects_as_decoded() -> None:
    """A new decode path must not silently acquire transaction authority.

    The marker is opt-in, so the risk it carries is a decode site that forgets
    it.  This reads the module and refuses that, which is cheaper and more
    durable than trusting six call sites to stay marked.
    """

    source = Path(legacy_codec.__file__).read_text()
    tree = ast.parse(source)
    calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_subject_factory"
    ]

    assert len(calls) == 6
    for call in calls:
        markers = [
            keyword for keyword in call.keywords if keyword.arg == "decoded"
        ]
        assert len(markers) == 1, f"legacy_codec.py:{call.lineno} is unmarked"
        assert markers[0].value.value is True, f"legacy_codec.py:{call.lineno}"


def test_a_decoded_subject_can_still_be_rebound_by_asking() -> None:
    """Unbound is the default, not a dead end: the named mint is still there."""

    with _canonical_validation_session(CanonicalSessionPhase.PROJECTED_PREPARATION):
        live = _subject(SUBJECT_REF, 0x1200)
        from_payload = authority_ids._subject_factory(
            model.SemanticSubjectRef,
            decoded=True,
            kind=model.SemanticSubjectKind.BLOCK,
            role=model.SemanticSubjectRole.PLANNED_HELPER,
            block_ref=SUBJECT_REF,
            anchor_ea=0x1200,
            locator=model.BlockSubjectLocator(SUBJECT_REF, 0x1200),
        )

        rebound = transaction_subject_ref(from_payload.subject_id)

        assert rebound is subject_join_ref(live)


def test_the_observed_seam_refusal_has_its_own_provenance() -> None:
    """A rebind failure must not be reported as an inventory failure.

    The observed rebind used to sit inside the inventory ``try``, so a refusal
    at the seam surfaced as ``observed_inventory`` and sent a reader to the
    wrong stage.  The behavioural half of this lives in
    ``tests/system/runtime`` (the observed revalidation fixture needs
    ``d810.hexrays``, which a unit test may not import); this half pins the
    structure that decides the label: the rebind has a ``try`` of its own, and
    the inventory build is not in it.
    """

    tree = ast.parse(Path(transaction_api.__file__).read_text())

    def calls(node, name):
        return [
            call for statement in node
            for call in ast.walk(statement)
            if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id == name
        ]

    observed = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Try)
        and calls(node.body, "_record_route_authority_rebind")
        and any(calls(handler.body, "_observed_live_binding_failure")
                for handler in node.handlers)
    ]

    assert len(observed) == 1
    (node,) = observed
    # The rebind is alone in its own try: an inventory failure and a seam
    # refusal can no longer arrive under one label.
    assert not calls(node.body, "_build_semantic_graph_inventory")
    assert not calls(node.body, "capture_observed_route_materialization")
    stages = {
        literal.value
        for handler in node.handlers
        for call in calls(handler.body, "_observed_live_binding_failure")
        for literal in call.args
        if isinstance(literal, ast.Constant) and isinstance(literal.value, str)
    }
    assert stages == {"observed_route_authority_rebind"}


def test_the_seam_recorder_does_not_freeze_this_modules_debug_flag(caplog) -> None:
    """A cached level flag read early and often disables later diagnostics.

    ``logger.debug_on`` is a ``LevelFlag`` that refreshes on a logging *config
    version* counter, not on a level change (``core/logging.py``).  Reading it
    once per transaction -- which is what the seam recorder would do if it were
    guarded -- caches ``False`` for this module's logger for the rest of the
    process and silently disables every later ``debug_on``-guarded diagnostic,
    such as the native-origin subset acceptance line at
    ``transaction_api._observed_native_origin_mismatch_diagnostics``.

    The assertion has to be on ``debug_on`` itself.  A plain
    ``logger.debug(...)`` probe proves nothing here: ``caplog.set_level`` calls
    ``Logger.setLevel``, which clears the *stdlib* ``isEnabledFor`` cache, so
    the probe is captured whether or not the ``LevelFlag`` is stale.  Only the
    flag the guard actually consults distinguishes the two.
    """

    logger_name = "d810.transforms.unflatten_authority.transaction_api"
    module_logger = transaction_api.logger
    previous = module_logger.level
    # Both outcomes, because the recorder logs on two branches and a guard on
    # either of them freezes the flag just as effectively.
    verified = _bundle()
    unverified = _emitted_bundle()
    try:
        # Reproduce production ordering: DEBUG is off when the transaction
        # runs, so a guarded recorder reads the flag and caches ``False``.
        # The explicit level plus version bump is what makes this test
        # discriminate rather than depend on the ambient suite level.
        module_logger.setLevel(d810_logging.WARNING)
        d810_logging.LevelFlag.bump_config_version()

        with _canonical_validation_session(
            CanonicalSessionPhase.PROJECTED_PREPARATION,
        ):
            assert transaction_api._record_route_authority_rebind(
                verified, phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            ) is RouteRebindVerification.PRODUCER_RECORDS_VERIFIED
            assert transaction_api._record_route_authority_rebind(
                unverified, phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            ) is RouteRebindVerification.PRODUCER_ARENA_CLOSED

        caplog.set_level(logging.DEBUG, logger=logger_name)

        # This is the assertion that fails when the guard is restored: the
        # recorder above would have frozen the flag before the level changed,
        # and ``LevelFlag`` does not notice a level change.
        assert bool(module_logger.debug_on)

        module_logger.debug("probe after the seam recorder ran")
        assert any(
            record.getMessage() == "probe after the seam recorder ran"
            for record in caplog.records
        )
    finally:
        module_logger.setLevel(previous)
        d810_logging.LevelFlag.bump_config_version()


def test_the_debug_flag_probe_would_catch_a_restored_guard(caplog) -> None:
    """Prove the assertion above discriminates, instead of trusting that it does.

    This freezes the flag exactly the way a restored ``if logger.debug_on:``
    guard in the seam recorder would -- by evaluating it once while DEBUG is
    off -- and then shows that the plain ``logger.debug`` probe still passes
    while the ``debug_on`` assertion fails.  Without this, the test above could
    be asserting something that is true either way.
    """

    logger_name = "d810.transforms.unflatten_authority.transaction_api"
    module_logger = transaction_api.logger
    previous = module_logger.level
    try:
        # Start from a genuinely refreshed flag: ``LevelFlag`` only recomputes
        # when the config version moves, so a stale value from an earlier test
        # would make this prove nothing in either direction.
        module_logger.setLevel(d810_logging.WARNING)
        d810_logging.LevelFlag.bump_config_version()
        frozen = bool(module_logger.debug_on)  # what a restored guard would do
        assert frozen is False

        caplog.set_level(logging.DEBUG, logger=logger_name)
        module_logger.debug("probe under a frozen level flag")

        # The stdlib cache was cleared by ``setLevel``, so the probe is
        # captured...
        assert any(
            record.getMessage() == "probe under a frozen level flag"
            for record in caplog.records
        )
        # ...while the flag the guard consults is still stale.  That gap is the
        # whole defect, and it is why the test above asserts on ``debug_on``.
        assert bool(module_logger.debug_on) is False
    finally:
        module_logger.setLevel(previous)
        d810_logging.LevelFlag.bump_config_version()


def _prepared_from_the_real_fixture(bundle_state: str):
    """Run the real preparation with the proposal's bundle in a chosen state."""

    values = test_bind._compiler_guarded_convert_to_goto_case(include_graphs=True)
    plan, attempt, source, projected = values[1], values[5], values[6], values[7]
    proposal = plan.unflatten_proposal
    if bundle_state == "dead":
        # Exactly what the emission does: build the bundle inside a phase that
        # ends before the transaction runs.
        with route_authority_phase("test-emission"):
            evidence = canonical_semantic_evidence_from_proofs(
                native_key=proposal.route_evidence.native_key,
                generation=proposal.route_evidence.generation,
                proofs=proposal.route_evidence.route_proofs,
            )
        plan = replace(plan, unflatten_proposal=replace(proposal, route_evidence=evidence))
    elif bundle_state == "absent":
        evidence = materialize_route_evidence(proposal.route_evidence)
        plan = replace(plan, unflatten_proposal=replace(proposal, route_evidence=evidence))
    raw_effect = check_effectful_reachability_preserved(source, post_cfg=projected)
    gates = GenericCfgGateBundle(
        check_entry_reachability_not_collapsed(source, post_cfg=projected),
        raw_effect,
        raw_effect,
        check_terminal_reachability_preserved(source, post_cfg=projected),
    )
    return transaction_api.prepare_unflatten_authority(
        source=source,
        projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan,
        attempt_id=attempt,
        generic_gates=gates,
    )


@pytest.mark.parametrize(
    "bundle_state,expected",
    (
        ("live", RouteRebindVerification.PRODUCER_RECORDS_VERIFIED),
        ("dead", RouteRebindVerification.PRODUCER_ARENA_CLOSED),
        ("absent", RouteRebindVerification.PRODUCER_UNBOUND),
    ),
)
def test_the_seam_outcome_survives_the_session_on_the_result(
    bundle_state: str, expected: RouteRebindVerification,
) -> None:
    """The verification rides the result, so it outlives the arena that decided it.

    The session's copy dies with the session and the producer's arena is gone
    too, so after a transaction the only thing that can still answer "what did
    the seam actually verify" is the result object.  Before this it was an INFO
    log line, which no consumer can read.
    """

    result = _prepared_from_the_real_fixture(bundle_state)

    assert type(result) is model.UnflattenAuthorityPreparationAccepted
    assert result.route_authority_verification is expected
    # The session that decided it is closed: the value is carried, not queried.
    assert active_canonical_session() is None
    with pytest.raises(RuntimeJoinRejected, match="requires an active canonical"):
        transaction_route_verification(result.prepared.proposal.route_evidence)


def test_the_seam_outcome_is_a_record_of_what_was_checked_never_a_grant() -> None:
    """It is non-authoritative: an absent value is not a rejection.

    Nothing consults it to decide authority.  A result built without it -- any
    caller constructing one directly -- is valid, and a result carrying the
    weakest outcome is still accepted.
    """

    result = _prepared_from_the_real_fixture("absent")

    assert result.verdict.accepted
    assert result.route_authority_verification is (
        RouteRebindVerification.PRODUCER_UNBOUND
    )
    without = model.UnflattenAuthorityPreparationAccepted(
        result.prepared, result.verdict,
    )
    assert without.route_authority_verification is None
    with pytest.raises(TypeError, match="must be a RouteRebindVerification"):
        model.UnflattenAuthorityPreparationAccepted(
            result.prepared, result.verdict,
            route_authority_verification="producer-unbound",
        )


def test_the_projected_seam_refusal_has_its_own_provenance() -> None:
    """The projected seam refusal is its own stage, like the observed one.

    It used to sit inside the preparation's several-hundred-line ``try``, whose
    single handler reports a generic ``PROJECTED_BINDING_FAILED`` with the
    plan's own fingerprint, so a reader could not tell a seam refusal from any
    other preparation failure.
    """

    tree = ast.parse(Path(transaction_api.__file__).read_text())

    def calls(nodes, name):
        return [
            call for statement in nodes
            for call in ast.walk(statement)
            if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id == name
        ]

    projected = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Try)
        and calls(node.body, "_record_route_authority_rebind")
        and any(
            calls(handler.body, "_projected_route_authority_rebind_failure")
            for handler in node.handlers
        )
    ]

    assert len(projected) == 1
    (node,) = projected
    # Alone in its own try: the preparation body is not under this handler.
    assert not calls(node.body, "_build_semantic_graph_inventory")
    assert not calls(node.body, "capture_source_route_materialization")
    stages = {
        literal.value
        for handler in node.handlers
        for call in calls(handler.body, "_projected_route_authority_rebind_failure")
        for literal in call.args
        if isinstance(literal, ast.Constant) and isinstance(literal.value, str)
    }
    assert stages == {"projected_route_authority_rebind"}


def test_a_refused_projected_seam_reports_its_own_stage_and_fingerprint(
    monkeypatch,
) -> None:
    """The behavioural half: a distinct fingerprint and a distinct detail."""

    values = test_bind._compiler_guarded_convert_to_goto_case(include_graphs=True)
    plan, attempt, source, projected = values[1], values[5], values[6], values[7]
    raw_effect = check_effectful_reachability_preserved(source, post_cfg=projected)
    gates = GenericCfgGateBundle(
        check_entry_reachability_not_collapsed(source, post_cfg=projected),
        raw_effect,
        raw_effect,
        check_terminal_reachability_preserved(source, post_cfg=projected),
    )
    arguments = {
        "source": source,
        "projection": CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        "plan": plan,
        "attempt_id": attempt,
        "generic_gates": gates,
    }
    accepted = transaction_api.prepare_unflatten_authority(**arguments)
    assert type(accepted) is model.UnflattenAuthorityPreparationAccepted

    def _refused(evidence, *, phase):
        raise RuntimeJoinRejected("the projected seam refuses this bundle")

    monkeypatch.setattr(transaction_api, "_record_route_authority_rebind", _refused)
    refused = transaction_api.prepare_unflatten_authority(**arguments)

    assert type(refused) is model.UnflattenAuthorityPreparationRejected
    assert refused.verdict.rejection_detail == "projected_route_authority_rebind"
    assert refused.verdict.candidate_fingerprint != (
        accepted.verdict.candidate_fingerprint
    )
    assert refused.verdict.candidate_fingerprint == (
        transaction_api._unavailable_candidate_fingerprint(
            "projected-route-authority-rebind"
        )
    )


def _verdict(**overrides):
    payload = {
        "accepted": False,
        "phase": model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        "reason": model.UnflattenAuthorityReason.LIVE_BINDING_FAILED,
        "authority_id": authority_ids.authority_id("verdict-sidecar-authority"),
        "binding_id": authority_ids.authority_id("verdict-sidecar-binding"),
        "case_id": None,
        "candidate_fingerprint": authority_ids.authority_id("verdict-sidecar-candidate"),
        "safety_case": None,
        "failed_obligations": (),
    }
    payload.update(overrides)
    return model.UnflattenAuthorityVerdict(**payload)


def test_the_verdict_sidecar_moves_no_canonical_byte_and_no_content_id() -> None:
    """Content and provenance stay separate: same bytes, same IDs, same value."""

    bound = _verdict(
        _route_authority_verification=RouteRebindVerification.PRODUCER_ARENA_CLOSED,
    )
    unbound = _verdict()

    assert bound.route_authority_verification is (
        RouteRebindVerification.PRODUCER_ARENA_CLOSED
    )
    assert unbound.route_authority_verification is None
    assert bound == unbound
    assert authority_ids.canonical_bytes(bound) == authority_ids.canonical_bytes(
        unbound
    )
    assert authority_ids.content_id(
        "unflatten.verdict-sidecar.v1", bound,
    ) == authority_ids.content_id("unflatten.verdict-sidecar.v1", unbound)
    assert authority_ids.authority_id(bound) == authority_ids.authority_id(unbound)
    # ...and inside a container, which is how a verdict actually reaches a seal.
    assert authority_ids.canonical_bytes(
        (bound, unbound)
    ) == authority_ids.canonical_bytes((unbound, unbound))
    assert "_route_authority_verification" not in repr(bound)


def test_a_persisted_verdict_decodes_without_the_sidecar() -> None:
    """Provenance is process-local: it is never encoded and never comes back."""

    bound = _verdict(
        _route_authority_verification=RouteRebindVerification.PRODUCER_UNBOUND,
    )

    decoded = authority_ids.canonical_decode(authority_ids.canonical_bytes(bound))

    assert decoded == bound
    assert decoded.route_authority_verification is None


def test_the_generic_walkers_tolerate_a_detached_verdict() -> None:
    """A detached copy leaves the slot *unwritten* -- the shape that raised in 5b-2."""

    bound = _verdict(
        _route_authority_verification=RouteRebindVerification.PRODUCER_RECORDS_VERIFIED,
    )

    detached = bind._detached_canonical_copy(bound, {})

    with pytest.raises(AttributeError):
        object.__getattribute__(detached, "_route_authority_verification")
    assert detached.route_authority_verification is None
    assert detached == bound
    assert authority_ids.canonical_bytes(detached) == authority_ids.canonical_bytes(
        bound
    )
    assert bind._registry_structural_snapshot(
        detached
    ) == bind._registry_structural_snapshot(bound)
    # Revalidating the rebuilt record must not raise on the unwritten slot.
    model.UnflattenAuthorityVerdict.__post_init__(detached)


def test_the_verdict_sidecar_is_in_the_closed_set_and_outside_the_schema() -> None:
    assert RUNTIME_VERDICT_SIDECAR_FIELD in RUNTIME_AUTHORITY_SIDECAR_FIELDS
    assert RUNTIME_VERDICT_SIDECAR_FIELD == "_route_authority_verification"
    assert RUNTIME_VERDICT_SIDECAR_FIELD not in authority_ids._RECORD_FIELDS[
        model.UnflattenAuthorityVerdict
    ]
    assert all(
        field.compare is False and field.repr is False
        for field in fields(model.UnflattenAuthorityVerdict)
        if field.name == RUNTIME_VERDICT_SIDECAR_FIELD
    )
    with pytest.raises(TypeError, match="must be a RouteRebindVerification"):
        _verdict(_route_authority_verification="producer-unbound")
