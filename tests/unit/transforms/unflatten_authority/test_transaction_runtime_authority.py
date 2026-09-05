"""The producer/transaction seam is a rebind, never an adoption.

The producer's arena is owned by the emission and is already closed when the
authority transaction reads the plan.  These tests pin that the transaction
opens its *own* arena, that the seam verifies the producer's claims before
minting, that nothing joins without passing through the seam, and that a
refusal at the seam abstains through the transaction's existing ``ValueError``
boundary instead of escaping.
"""

from __future__ import annotations

from dataclasses import replace

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
    route_authority_phase,
    route_join_binding,
    runtime_semantic_evidence_from_proofs,
    runtime_semantic_route_scope,
)
from d810.core.runtime_identity import (
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
)
from d810.transforms.unflatten_authority.runtime_authority import (
    rebind_route_evidence,
    transaction_authority_session,
    transaction_route_arena,
    transaction_route_binding,
)
from d810.analyses.control_flow.graph_checks import (
    check_effectful_reachability_preserved,
    check_entry_reachability_not_collapsed,
    check_terminal_reachability_preserved,
)
from d810.transforms.cfg_transaction import CfgProjection
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
        projected = rebind_route_evidence(evidence)
        projected_refs = projected.proof_refs
    with _canonical_validation_session(CanonicalSessionPhase.OBSERVED_REVALIDATION):
        observed = rebind_route_evidence(evidence)

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

        binding = rebind_route_evidence(evidence)

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
        assert len(first.proof_refs) == len(evidence.route_proofs)


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
        binding = rebind_route_evidence(unbound)

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
        rebound = rebind_route_evidence(evidence)

        assert evidence.atomic_group_id == before_group
        assert tuple(proof.proof_id for proof in evidence.route_proofs) == before_ids
        assert rebound.atomic_group_id == before_group
        # The producer's binding is still the producer's.
        assert evidence.route_binding is not rebound
        assert evidence.route_binding.arena is not rebound.arena


def test_the_binding_dies_with_the_session_that_minted_it() -> None:
    evidence = _emitted_bundle()

    with _canonical_validation_session(CanonicalSessionPhase.PROJECTED_PREPARATION):
        binding = rebind_route_evidence(evidence)
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
