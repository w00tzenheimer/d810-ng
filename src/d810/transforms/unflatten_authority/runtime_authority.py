"""The transaction's side of the producer/transaction runtime authority seam.

The producer and the transaction are two scopes, and a runtime reference is
only meaningful inside the scope that minted it.  The producer's arena is owned
by the emission phase and is *already closed* by the time the authority
transaction reads the plan, so the transaction cannot join on the producer's
references and must not adopt the producer's arena either -- adoption would
make one scope's lifetime depend on another's.

The seam is therefore an explicit, named **rebind**:

``rebind_route_evidence`` verifies the producer binding a bundle carries -- same
group, same proof fingerprints, and, while the producer arena is still open,
the same proof *records* -- and then mints fresh references for that bundle in
the arena the active :class:`CanonicalValidationSession` owns.  Nothing is
copied and no content identity moves; ``atomic_group_id`` and every
``proof_id`` stay exactly the sha256 fingerprints they were, and remain
non-authoritative for runtime joins.

``transaction_route_binding`` is the only way a join reaches that authority.  A
bundle the transaction never rebound -- decoded from persistence, reconstructed
field by field, or simply never handed to the seam -- is refused with
:class:`RuntimeJoinRejected`.  That is a ``ValueError``, so the refusal travels
through the transaction's existing ``except (TypeError, ValueError)`` boundary
and becomes a rejected verdict rather than an exception escaping into a
decompilation.

Semantic subjects take the same seam by a different route.  A subject is not
handed across as one bundle: the transaction *reconstructs* the same subject
from an inventory, from a claim member and from a catalog witness, so its
reference is interned on the canonical ``subject_id`` once per session
(:func:`transaction_subject_ref`) and written into the record at construction,
before it seals.  A subject the producer built carries none -- there is no
session during the emission -- and :func:`subject_join_ref` refuses it rather
than inventing one.
"""

from __future__ import annotations

from dataclasses import dataclass

from d810.analyses.control_flow.semantic_route_evidence import (
    CanonicalSemanticEvidence,
    RouteAuthorityBinding,
    rebind_route_authority,
)
from d810.core.runtime_identity import (
    RUNTIME_SUBJECT_SIDECAR_FIELD,
    RuntimeAuthorityArena,
    RuntimeAuthorityKind,
    RuntimeAuthorityRef,
    RuntimeJoinRejected,
)

from .canonical_session import CanonicalValidationSession, active_canonical_session


@dataclass(frozen=True, slots=True)
class TransactionSubjectRecord:
    """The immutable record one subject reference names inside a session.

    A reference names a record, and a semantic subject is *identified* by its
    canonical ``subject_id`` -- a fingerprint of ``(kind, role, locator)``.
    That fingerprint is therefore what the arena stores: it is complete before
    the mint, it is never touched again, and it keeps the arena free of a
    strong reference to the subject record itself, so nothing here can keep a
    record graph alive past the session.
    """

    subject_id: str


def transaction_authority_session() -> CanonicalValidationSession:
    """Return the session that owns runtime authority here, or refuse.

    A runtime join outside a transaction session has no owner for its
    references, so there is nothing to answer with.  Refusing is not a
    limitation: it is the reason the arena is session-scoped at all.
    """

    session = active_canonical_session()
    if session is None:
        raise RuntimeJoinRejected(
            "a runtime authority join requires an active canonical validation "
            "session to own its references"
        )
    if session.closed:
        raise RuntimeJoinRejected(
            "the canonical validation session that owned this runtime "
            "authority is closed"
        )
    return session


def transaction_route_arena() -> RuntimeAuthorityArena:
    """Return the active transaction session's own runtime authority arena."""

    return transaction_authority_session().route_arena


def rebind_route_evidence(
    evidence: CanonicalSemanticEvidence,
) -> RouteAuthorityBinding:
    """Rebind one producer bundle into this transaction, and return its authority.

    This is *the* seam step.  It is idempotent per session and per exact
    occurrence: the transaction reads ``proposal.route_evidence`` from many
    places, and every one of them must reach the same references, so a repeat
    call returns the binding this session already minted instead of minting a
    second, unequal authority for one bundle.

    The producer's arena is never adopted and never closed here; only its
    claims about the bundle are checked, by
    :func:`d810.analyses.control_flow.semantic_route_evidence.rebind_route_authority`.
    """

    session = transaction_authority_session()
    existing = session.runtime_binding_for(evidence)
    if existing is not None:
        return existing
    binding = rebind_route_authority(evidence, arena=session.route_arena)
    session.store_runtime_binding(evidence, binding)
    return binding


def transaction_route_binding(
    evidence: CanonicalSemanticEvidence,
) -> RouteAuthorityBinding:
    """Return this transaction's authority for ``evidence``, or refuse the join.

    Unlike :func:`rebind_route_evidence` this never mints.  A join asks a
    question about records the transaction already accepted; if the bundle in
    hand was never rebound at the seam, the honest answer is that this scope
    has no authority over it, not that it should quietly acquire some.
    """

    if type(evidence) is not CanonicalSemanticEvidence:
        raise TypeError("route join requires canonical semantic evidence")
    session = transaction_authority_session()
    binding = session.runtime_binding_for(evidence)
    if binding is None:
        raise RuntimeJoinRejected(
            "canonical semantic evidence was not rebound into this "
            "transaction; rebind it explicitly before joining on it"
        )
    if not binding.is_live:
        raise RuntimeJoinRejected(
            "the runtime authority arena of this transaction is closed"
        )
    return binding


def transaction_subject_ref(subject_id: str) -> RuntimeAuthorityRef | None:
    """Return the reference this transaction names ``subject_id`` by, if any.

    ``None`` is the honest answer outside a transaction session, and it is the
    normal answer: the producer builds semantic subjects too -- inside the
    unflatten emission, where no canonical validation session exists -- and
    those subjects legitimately carry no transaction authority.  They are
    values crossing a seam, exactly like a decoded record, and a join must
    refuse them rather than invent an authority for them.
    """

    if type(subject_id) is not str:
        raise TypeError("a subject reference requires an exact subject id")
    session = active_canonical_session()
    if session is None or session.closed:
        return None
    return session.interned_ref(
        subject_id,
        RuntimeAuthorityKind.SUBJECT,
        TransactionSubjectRecord(subject_id),
    )


def subject_join_ref(subject: object) -> RuntimeAuthorityRef:
    """Return the runtime authority of ``subject``, or refuse the join.

    This is the only way a join reaches a subject's reference.  A subject
    constructed outside a transaction session -- every subject the producer
    put into the proposal -- carries none and is refused here, rather than
    being silently compared by content by whichever join saw it first.

    The parameter is untyped on purpose: this module sits *below*
    ``model`` in the package's import order (``model`` -> ``ids`` -> here), so
    it cannot name ``SemanticSubjectRef``.  It does not need to: the slot
    either holds a subject reference or the value is not one, and both are
    checked.
    """

    ref = getattr(subject, RUNTIME_SUBJECT_SIDECAR_FIELD, None)
    if ref is None:
        raise RuntimeJoinRejected(
            "semantic subject was not minted by this transaction and carries "
            "no runtime authority; it can only be compared by content"
        )
    if type(ref) is not RuntimeAuthorityRef or ref.kind is not RuntimeAuthorityKind.SUBJECT:
        raise TypeError("semantic subject sidecar is not a subject reference")
    session = transaction_authority_session()
    if not session.route_arena.owns(ref):
        raise RuntimeJoinRejected(
            "semantic subject was minted by another transaction session"
        )
    return ref


__all__ = [
    "TransactionSubjectRecord",
    "rebind_route_evidence",
    "subject_join_ref",
    "transaction_authority_session",
    "transaction_route_arena",
    "transaction_route_binding",
    "transaction_subject_ref",
]
