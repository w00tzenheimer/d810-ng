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
"""

from __future__ import annotations

from d810.analyses.control_flow.semantic_route_evidence import (
    CanonicalSemanticEvidence,
    RouteAuthorityBinding,
    rebind_route_authority,
)
from d810.core.runtime_identity import RuntimeAuthorityArena, RuntimeJoinRejected

from .canonical_session import CanonicalValidationSession, active_canonical_session


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


__all__ = [
    "rebind_route_evidence",
    "transaction_authority_session",
    "transaction_route_arena",
    "transaction_route_binding",
]
