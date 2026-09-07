"Read-only branch ownership proofs for state-machine reconstruction.\n\nThis module classifies conditional state-machine edges as semantic source\ncontrol flow, opaque/BCF residue, or unresolved evidence.  It deliberately\ndoes not build graph modifications.  CFG lowering may consume trusted proof\nrows later, but preanalysis owns producing and explaining the proof.\n"

from __future__ import annotations

import json
from collections.abc import Callable, Collection
from dataclasses import dataclass, field
from enum import Enum

from d810.analyses.control_flow.dispatcher_resolution import StateDispatcherMap
from d810.analyses.control_flow.evidence_candidate import EvidenceCandidate
from d810.analyses.control_flow.producer_registration import (
    UNSPECIFIED_PRODUCER,
    ProducerIdentity,
    ProducerRegistration,
    ProducerRegistrationAuthority,
    ProducerRegistrationToken,
    checked_registration_token,
    identities_for_names,
    producer_registration_of,
)

_MASK64 = 0xFFFFFFFFFFFFFFFF

#: Producer name carried by a row that never named one.  Deliberately *not* a
#: member of :class:`BranchOwnershipOracleKind`: an absent producer is
#: unregistered, never a registered default (d81-9q6e review round 2).  Before
#: this, an omitted ``oracle_kind`` resolved to ``PREANALYSIS_BRANCH_OWNERSHIP``
#: -- an enumerated member -- so ``producer_registration`` reported
#: ``REGISTERED`` and a dict that simply left the field out minted
#: ``SEMANTIC_BRIDGE``, bypassing the registration gate by omission.  Review
#: round 3 made the sentinel unvouchable as well: it names the *absence* of a
#: producer, and absence can never be vouched for after the fact, so no
#: :class:`~d810.analyses.control_flow.producer_registration.ProducerIdentity`
#: can be built from it.
UNSPECIFIED_BRANCH_OWNERSHIP_ORACLE = UNSPECIFIED_PRODUCER


class BranchOwnershipOracleKind(str, Enum):
    """Which producer minted a :class:`BranchOwnershipProof`.

    ``oracle_kind`` used to be a free-form string with a trusted-looking
    default, so an unrecognised (or absent) producer silently presented itself
    as ``preanalysis_branch_ownership``.  An absent name now resolves to
    :data:`UNSPECIFIED_BRANCH_OWNERSHIP_ORACLE`, which is not a member here.
    Enumerating the producers makes the provenance checkable:
    :func:`branch_ownership_proof_from_any` normalises a recognised name to
    a member here, and :attr:`BranchOwnershipProof.is_known_oracle`
    reports whether the proof came from a producer this codebase knows about.

    Members subclass ``str``, so every existing ``==`` comparison, ``in``-set
    test, dict lookup and JSON encoding against the bare name keeps working.
    Use :attr:`BranchOwnershipProof.oracle_kind_name` wherever a plain ``str``
    is required -- ``str(member)`` renders ``"BranchOwnershipOracleKind.X"``,
    not the value.
    """

    # d810.analyses.control_flow.branch_ownership
    PREANALYSIS_BRANCH_OWNERSHIP = "preanalysis_branch_ownership"
    UNRESOLVED = "unresolved"
    EXPLICIT_OPAQUE_PROVENANCE = "explicit_opaque_provenance"
    DAG_TERMINAL_FRONTIER = "dag_terminal_frontier"
    DAG_EDGE_EQUIVALENCE = "dag_edge_equivalence"
    TERMINAL_SELECTOR_BACKEDGE = "branch_ownership_terminal_selector_backedge"
    # d810.analyses.control_flow.branch_ownership_oracle
    MOPTRACKER = "moptracker_branch_ownership"
    Z3_JUMPFIXER = "z3_jumpfixer_branch_ownership"
    # d810.analyses.control_flow.switch_case_transition_analysis
    SWITCH_CASE_RETURN_FRONTIER = "switch_case_return_frontier"
    SWITCH_CASE_BRANCH_OWNERSHIP = "switch_case_branch_ownership"
    SWITCH_CASE_DISPATCHER_ROW_DIAGNOSTIC = "switch_case_dispatcher_row_diagnostic"
    SWITCH_CASE_TRANSITION_UNRESOLVED = "switch_case_transition_unresolved"
    # d810.backends.hexrays.evidence.ollvm_carrier
    OLLVM_CARRIER = "ollvm_carrier_branch_ownership"


class BranchOwnershipEvidenceKey(str, Enum):
    """Evidence-bag keys that are load-bearing rather than diagnostic.

    Most of ``BranchOwnershipProof.evidence`` is free-form explanation, but a
    few keys gate real decisions.  Naming them keeps a safety guard from
    hinging on an undeclared string literal typed in two places.

    ``SIDE_EFFECT_GUARD_REASON``
        Set by an oracle that proved a branch condition constant but refused to
        authorize discarding the unselected arm because that arm owns payload
        side effects.  :attr:`BranchOwnershipProof.vetoes_fallback_refinement`
        keys off its presence.
    """

    SIDE_EFFECT_GUARD_REASON = "side_effect_guard_reason"


#: Who, if anyone, vouches for the producer that minted a row.
#:
#: Aliased to the shared :class:`ProducerRegistration` so branch ownership and
#: transition trust cannot drift apart on what "registered" means.  The verdict
#: is read from a minted
#: :class:`~d810.analyses.control_flow.producer_registration.ProducerRegistrationToken`,
#: never from the producer name the row claims: review round 3 showed a foreign
#: row could simply name ``moptracker_branch_ownership`` and report
#: ``REGISTERED``.
BranchOwnershipProducerRegistration = ProducerRegistration


class BranchOwnershipTrustProvenance(str, Enum):
    """Whether the row's trust value was a real boolean decision.

    ``trusted`` used to be coerced with ``bool(value)`` at the duck-typed
    boundary, so the string ``"false"`` -- and any other non-empty string, or
    ``1`` -- became a *trusted* row.  A non-``bool`` trust value is now
    recorded as ``MALFORMED``: the row keeps ``trusted=False`` and its
    :attr:`BranchOwnershipProof.authority` is
    :attr:`BranchOwnershipAuthority.UNRESOLVED_PROVENANCE`, never a grant.
    """

    WELL_FORMED = "well_formed"
    MALFORMED = "malformed"


class BranchOwnershipAuthority(str, Enum):
    """The single typed verdict a proof row carries.

    Consumers previously had to recompose ``trusted and proof_kind == ...`` to
    learn what a proof permits, which put a bare bool and a bare string on the
    critical path to a semantic DAG bridge.  This enum is the one value that
    answers "what may be done with this row?".

    ``SEMANTIC_BRIDGE``
        Real source-program control flow.  May be preserved as an explicit
        state-DAG bridge.  May **not** authorize branch removal.

    ``NONSEMANTIC_REWRITE``
        Proven obfuscation residue.  May authorize removing/retargeting this
        exact arm after exact edge-identity matching.  May **not** authorize
        semantic bridging.

    ``DIAGNOSTIC_ONLY``
        Explains why no mutation is allowed.  Authorizes nothing.  Predicate
        proofs (``OPAQUE_ALWAYS_*``), terminal frontiers, equivalent arms and
        every untrusted row land here: they are evidence, not permission.

    ``UNRESOLVED_PROVENANCE``
        The row could not be trusted to *mean* anything: its trust value was
        not a boolean, or the producer that minted it is not registered and
        nobody adapted it.  Authorizes nothing, and is deliberately distinct
        from ``DIAGNOSTIC_ONLY`` so a consumer can refuse the row loudly
        instead of silently treating malformed provenance as ordinary
        evidence.
    """

    SEMANTIC_BRIDGE = "semantic_bridge"
    NONSEMANTIC_REWRITE = "nonsemantic_rewrite"
    DIAGNOSTIC_ONLY = "diagnostic_only"
    UNRESOLVED_PROVENANCE = "unresolved_provenance"


def _enum_value(value: object) -> str:
    """Render an enum member as its value, anything else via ``str``.

    ``str(SomeStrEnum.MEMBER)`` returns ``"SomeStrEnum.MEMBER"``, not the
    value, so a plain ``str()`` coercion would corrupt every serialized row
    the moment a producer switched from a literal to a member.
    """
    if isinstance(value, Enum):
        return str(value.value)
    return str(value)


class BranchOwnershipProofKind(str, Enum):
    "Semantic ownership classification for one conditional branch arm.\n\n    These values describe the *meaning of one observed branch arm*, not the\n    graph edit to perform.  Keep that separation intact:\n\n    - Semantic-edge authority means a consumer may preserve the arm as source\n      program control flow or use it as an explicit state-DAG bridge.\n    - Nonsemantic-rewrite authority means a consumer may remove, retarget, or\n      bypass the arm after matching exact edge identity.\n    - Diagnostic-only authority means the row explains why no mutation is\n      allowed.\n\n    ``REAL_DATA_DEPENDENT``\n        The arm is controlled by real program data, such as password/input\n        bytes, an API result, or another value that belongs to the source\n        program.  This is semantic program structure.  A trusted proof may\n        authorize explicit DAG bridging/preservation.  It must not authorize\n        branch removal.\n\n    ``OPAQUE_ALWAYS_TRUE`` / ``OPAQUE_ALWAYS_FALSE``\n        The predicate outcome is proven constant under the relevant path\n        constraints and this row identifies the arm selected by that constant\n        outcome.  This is predicate authority only: it does not prove that the\n        selected arm is semantic, nor that a CFG rewrite may remove it.  The\n        complementary non-selected arm should be represented separately as\n        ``OBFUSCATION_RESIDUE_ARM`` when preanalysis can identify it.\n\n    ``EQUIVALENT_STATE_ARMS``\n        Both conditional arms resolve to the same semantic state/handler, so\n        the branch is not a meaningful source-level fork even if both CFG arms\n        are reachable.  This is useful for simplification diagnostics and\n        possible coalescing, but it is not enough by itself to delete one arm\n        unless a later consumer also proves the exact rewrite shape.\n\n    ``OBFUSCATION_RESIDUE_ARM``\n        The arm reaches a state-machine state that exists only as obfuscation\n        residue: for example a BCF false arm, selector backedge, dispatcher\n        residue state, or opaque branch target that should not appear as\n        recovered source control flow.  A trusted proof may authorize\n        nonsemantic branch rewrite after exact edge matching.  It must not\n        authorize semantic DAG bridging.\n\n    ``TERMINAL_RETURN_FRONTIER``\n        The arm identifies a return/exit frontier.  This is terminal ownership\n        evidence for return-frontier handling.  It is not opaque-branch proof\n        and does not authorize deleting a sibling arm.\n\n    ``UNRESOLVED``\n        Preanalysis saw a conditional arm but no trusted oracle classified it.  This\n        row is diagnostics only.  No CFG mutation or semantic bridge may be\n        justified from it.\n"

    REAL_DATA_DEPENDENT = "REAL_DATA_DEPENDENT"
    OPAQUE_ALWAYS_TRUE = "OPAQUE_ALWAYS_TRUE"
    OPAQUE_ALWAYS_FALSE = "OPAQUE_ALWAYS_FALSE"
    EQUIVALENT_STATE_ARMS = "EQUIVALENT_STATE_ARMS"
    OBFUSCATION_RESIDUE_ARM = "OBFUSCATION_RESIDUE_ARM"
    TERMINAL_RETURN_FRONTIER = "TERMINAL_RETURN_FRONTIER"
    UNRESOLVED = "UNRESOLVED"


TRUSTED_OPAQUE_PROVENANCE_KINDS = frozenset(
    {
        "ollvm_bcf_opaque_predicate",
        "opaque_bcf_branch",
        "proven_opaque_predicate",
    }
)


@dataclass(frozen=True, slots=True)
class BranchOwnershipProof:
    """One diagnostic proof row for a conditional state-machine branch arm."""

    proof_id: str
    proof_kind: BranchOwnershipProofKind | str
    trusted: bool
    reason: str
    source_block: int | None = None
    branch_arm: int | None = None
    source_state: int | None = None
    target_state: int | None = None
    target_entry: int | None = None
    predicate_block: int | None = None
    dispatcher_entry_block: int | None = None
    oracle_kind: BranchOwnershipOracleKind | str = UNSPECIFIED_BRANCH_OWNERSHIP_ORACLE
    evidence: dict[str, object] = field(default_factory=dict)
    payload: dict[str, object] = field(default_factory=dict)
    #: Minted by :meth:`BranchOwnershipRegistrationAuthority.bind`, never set by
    #: a producer.  ``None`` -- the only value a row or a direct construction
    #: can obtain -- means nobody vouched for the producer.
    registration: ProducerRegistrationToken | None = None
    trust_provenance: BranchOwnershipTrustProvenance = (
        BranchOwnershipTrustProvenance.WELL_FORMED
    )

    def __post_init__(self) -> None:
        """Refuse a non-boolean trust decision at construction time.

        In-tree producers pass a real ``bool``; anything else (``1``, ``0``,
        ``"true"``, ``"false"``, ``None``) is a provenance bug that used to be
        laundered into a trusted row by ``bool(value)``.  Duck-typed rows from
        outside the tree are not constructed directly: they go through
        :func:`branch_ownership_proof_from_any`, which converts a malformed
        trust value into an explicit ``MALFORMED`` verdict rather than raising.
        """
        if not isinstance(self.trusted, bool):
            raise TypeError(
                "BranchOwnershipProof.trusted must be a bool, got "
                f"{type(self.trusted).__name__!r} ({self.trusted!r}); "
                "use branch_ownership_proof_from_any() for untyped input"
            )
        checked_registration_token(self.registration)

    @property
    def proof_kind_name(self) -> str:
        kind = self.proof_kind
        if isinstance(kind, BranchOwnershipProofKind):
            return kind.value
        return str(kind)

    @property
    def oracle_kind_name(self) -> str:
        """The producer name as a plain ``str``, whatever the field holds."""
        return _enum_value(self.oracle_kind)

    @property
    def is_known_oracle(self) -> bool:
        """Whether this row *claims* a producer enumerated in this codebase.

        This is a claim and nothing more.  It is deliberately **not** consulted
        by :attr:`producer_registration` or :attr:`authority`: a foreign row can
        write any name it likes, and review round 3 reproduced exactly that --
        a dict naming ``moptracker_branch_ownership`` minting
        ``SEMANTIC_BRIDGE``.  Use it for diagnostics, never as authorization.
        """
        try:
            BranchOwnershipOracleKind(self.oracle_kind_name)
        except ValueError:
            return False
        return True

    @property
    def producer_registration(self) -> ProducerRegistration:
        """Who, if anyone, vouches for the producer that minted this row.

        Read from the minted token only.  A row that merely claims a
        recognized ``oracle_kind``, and a row constructed by hand, both report
        ``UNKNOWN``: registration is minted by
        :class:`BranchOwnershipRegistrationAuthority`, never claimed.
        """
        return producer_registration_of(
            self.registration,
            self.oracle_kind_name,
            domain=BranchOwnershipRegistrationAuthority.RECORD_DOMAIN,
        )

    @property
    def has_registered_trust(self) -> bool:
        """Whether a registered producer supplied a well-formed trusted row.

        This validates provenance only. Diagnostic predicate and terminal rows
        still grant no rewrite permission themselves; a producer combining
        them into a stronger proof must check this before using their claims.
        """
        return (
            self.trusted
            and self.trust_provenance is BranchOwnershipTrustProvenance.WELL_FORMED
            and self.producer_registration is not ProducerRegistration.UNKNOWN
        )

    @property
    def authority(self) -> BranchOwnershipAuthority:
        """What this row permits, as one typed verdict.

        Equivalent by construction to the pair of ``authorizes_*`` properties
        below, which now delegate here so the ``trusted``-bool-plus-kind-string
        composition exists in exactly one place.

        Two provenance gates sit in front of the grant verdicts:

        * a row whose trust value was not a boolean is
          ``UNRESOLVED_PROVENANCE``, whatever it claims to be;
        * a grant (``SEMANTIC_BRIDGE`` / ``NONSEMANTIC_REWRITE``) requires a
          producer that is registered or explicitly adapted.  An unknown
          producer abstains rather than granting.

        Registration gates *grants* only: an unknown producer's diagnostic row
        stays ``DIAGNOSTIC_ONLY``, because reclassifying evidence would lose
        information without making anything safer.
        """
        if self.trust_provenance is not BranchOwnershipTrustProvenance.WELL_FORMED:
            return BranchOwnershipAuthority.UNRESOLVED_PROVENANCE
        if not self.trusted:
            return BranchOwnershipAuthority.DIAGNOSTIC_ONLY
        kind = self.proof_kind_name
        if kind == BranchOwnershipProofKind.REAL_DATA_DEPENDENT.value:
            verdict = BranchOwnershipAuthority.SEMANTIC_BRIDGE
        elif kind == BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM.value:
            verdict = BranchOwnershipAuthority.NONSEMANTIC_REWRITE
        else:
            return BranchOwnershipAuthority.DIAGNOSTIC_ONLY
        if not self.has_registered_trust:
            return BranchOwnershipAuthority.UNRESOLVED_PROVENANCE
        return verdict

    @property
    def authorizes_nonsemantic_branch_rewrite(self) -> bool:
        """Whether this proof can authorize removing/retargeting a branch arm.

        This is deliberately narrower than ``trusted``.  A trusted proof can be
        terminal evidence, semantic branch evidence, or diagnostics.  Only
        proof rows that show this exact arm is nonsemantic may drive mutation
        that removes or bypasses that arm, and downstream consumers must still
        match exact edge identity before applying a rewrite.

        This property is semantic-edge authority, not raw CFG ownership
        authority.  A consumer that rewrites live/projected CFG must still prove
        the source block/arm is private to the edge, or lower through a
        clone/split primitive that makes it private first.
        """
        return self.authority is BranchOwnershipAuthority.NONSEMANTIC_REWRITE

    @property
    def authorizes_semantic_branch_bridge(self) -> bool:
        """Whether this proof can authorize preserving a branch as semantic.

        Only real data-dependent branch ownership is semantic-edge authority.
        Opaque and obfuscation-residue proofs may be strong enough to remove a
        nonsemantic arm, but they are not proof that the arm should appear in
        the recovered state DAG.
        """

        return self.authority is BranchOwnershipAuthority.SEMANTIC_BRIDGE

    @property
    def vetoes_fallback_refinement(self) -> bool:
        """Whether later, weaker oracles must not reclassify this proof.

        Some proofs are deliberately untrusted diagnostics because an oracle
        found evidence that prevents a rewrite.  For example, the Z3/JumpFixer
        oracle can prove a branch condition is constant but still veto removing
        the discarded arm because that arm owns payload side effects.  That
        result must stay sticky: a later fallback oracle may not reinterpret the
        same arm as disposable obfuscation residue and lose the safety guard.
        """

        return (
            self.proof_kind_name == BranchOwnershipProofKind.UNRESOLVED.value
            and not self.trusted
            and BranchOwnershipEvidenceKey.SIDE_EFFECT_GUARD_REASON.value
            in self.evidence
        )

    def to_diag_row(
        self,
        *,
        profile_name: str | None = None,
        maturity: str | None = None,
    ) -> dict[str, object]:
        payload = dict(self.payload)
        if profile_name is not None:
            payload.setdefault("profile_name", str(profile_name))
        if maturity is not None:
            payload.setdefault("maturity", str(maturity))
        return {
            "proof_id": self.proof_id,
            "proof_kind": self.proof_kind_name,
            "trusted": int(bool(self.trusted)),
            "reason": self.reason,
            "source_block": self.source_block,
            "branch_arm": self.branch_arm,
            "source_state": self.source_state,
            "target_state": self.target_state,
            "target_entry": self.target_entry,
            "predicate_block": self.predicate_block,
            "dispatcher_entry_block": self.dispatcher_entry_block,
            "oracle_kind": self.oracle_kind_name,
            "evidence": self.evidence,
            "payload": payload,
        }


class BranchOwnershipRegistrationAuthority(ProducerRegistrationAuthority):
    """The binder that mints branch-ownership producer registrations.

    Owned by whoever owns the trust decision -- the preanalysis pass that
    collects proofs, or the session that adapts an out-of-tree oracle.  It is
    the *only* way a :class:`BranchOwnershipProof` becomes registered.
    """

    RECORD_DOMAIN = "branch_ownership"
    RECORD_PRODUCER_FIELD = "oracle_kind"
    RECORD_REGISTRATION_FIELD = "registration"


def branch_ownership_registration_authority(
    *,
    adapted_producers: Collection[object] = (),
) -> BranchOwnershipRegistrationAuthority:
    """Create a fresh binder over the in-tree oracles.

    ``adapted_producers`` names out-of-tree oracles the *owner of the binder*
    vouches for; they are recognized as
    :attr:`ProducerRegistration.EXPLICITLY_ADAPTED`.  Vouching happens here,
    when the binder is built by code, and never from a name written on a row.

    A fresh authority (and fresh identity objects) on every call: there is no
    process-global registry for a stray import to extend, and identities are
    matched by object identity, so a look-alike built elsewhere is refused.
    """
    identities: list[ProducerIdentity] = list(
        identities_for_names(BranchOwnershipOracleKind)
    )
    identities.extend(
        identities_for_names(
            adapted_producers,
            registration=ProducerRegistration.EXPLICITLY_ADAPTED,
        )
    )
    return BranchOwnershipRegistrationAuthority(identities)


def registered_branch_ownership_proof(
    registrar: BranchOwnershipRegistrationAuthority,
    **fields: object,
) -> BranchOwnershipProof:
    """Mint an in-tree proof already bound to the oracle that produced it.

    ``fields["oracle_kind"]`` is a literal written by the *producing code* at
    the call site, never a value read off an evidence row -- rows do not reach
    this helper, and the binder still resolves the literal to one of its own
    identity objects before minting.  This is the only spelling in-tree
    producers use, so "who minted this row" has one answer per call site and
    stays greppable.
    """
    oracle_kind = fields.get("oracle_kind")
    if oracle_kind is None:
        raise ValueError(
            "an in-tree producer must name the oracle it is binding to; "
            "absence is never registered"
        )
    proof = BranchOwnershipProof(**fields)  # type: ignore[arg-type]
    return registrar.bind(proof, registrar.producer(oracle_kind))


def _normalized_oracle_kind(value: object) -> BranchOwnershipOracleKind | str:
    """Coerce a producer name to a member when recognised, else keep it.

    An absent or empty producer name resolves to
    :data:`UNSPECIFIED_BRANCH_OWNERSHIP_ORACLE`, which is not an enumerated
    member: nobody vouched for the row, so it is ``UNKNOWN`` to
    :attr:`BranchOwnershipProof.producer_registration` and cannot mint a grant.
    The old fallback named a *real* producer, ``PREANALYSIS_BRANCH_OWNERSHIP``,
    which made omission indistinguishable from that producer's own rows.
    """
    if isinstance(value, BranchOwnershipOracleKind):
        return value
    if value is None or value == "":
        return UNSPECIFIED_BRANCH_OWNERSHIP_ORACLE
    name = _enum_value(value)
    try:
        return BranchOwnershipOracleKind(name)
    except ValueError:
        return name


def branch_ownership_proof_candidate_from_any(
    value: object | None,
) -> EvidenceCandidate[BranchOwnershipProof]:
    """Parse an untyped ownership candidate into an explicit tri-state.

    The input is untyped by design -- producers outside this package attach
    dicts and duck-typed objects -- so this is the boundary where provenance is
    checked rather than assumed:

    ``ABSENT``
        No candidate was supplied.  A consumer may look at its next evidence
        source.

    ``MALFORMED``
        A candidate was supplied and could not be parsed: a required field was
        missing, or ``proof_kind`` held an unusable value.  This is terminal --
        a consumer must refuse, not fall through to weaker evidence, because
        falling through let an incomplete row buy a grant it could not earn
        (review round 3).

    ``PARSED``
        A proof row.  Note what parsing does *not* do: it never registers the
        producer.  ``trusted`` must be a real ``bool`` (``"true"``, ``1``,
        ``None`` are recorded as
        :attr:`BranchOwnershipTrustProvenance.MALFORMED` rather than coerced),
        and the producer name it carries stays a claim.  Registration is minted
        by :class:`BranchOwnershipRegistrationAuthority`, so a foreign row
        cannot authenticate its own producer whatever name it writes.
    """
    if value is None:
        return EvidenceCandidate.absent()
    if isinstance(value, BranchOwnershipProof):
        return EvidenceCandidate.parsed(value)
    if isinstance(value, dict):
        proof_id = value.get("proof_id")
        proof_kind = value.get("proof_kind")
        trusted = value.get("trusted")
        reason = value.get("reason")
    else:
        proof_id = getattr(value, "proof_id", None)
        proof_kind = getattr(value, "proof_kind", None)
        trusted = getattr(value, "trusted", None)
        reason = getattr(value, "reason", None)
    missing = tuple(
        name
        for name, field_value in (
            ("proof_id", proof_id),
            ("proof_kind", proof_kind),
            ("reason", reason),
        )
        if field_value is None
    )
    if missing:
        return EvidenceCandidate.malformed(
            "missing_required_field:" + ",".join(missing)
        )
    if isinstance(trusted, bool):
        trust_provenance = BranchOwnershipTrustProvenance.WELL_FORMED
        trusted_value = trusted
    else:
        trust_provenance = BranchOwnershipTrustProvenance.MALFORMED
        trusted_value = False

    def _field(name: str) -> object | None:
        if isinstance(value, dict):
            return value.get(name)
        return getattr(value, name, None)

    try:
        kind = (
            proof_kind
            if isinstance(proof_kind, BranchOwnershipProofKind)
            else BranchOwnershipProofKind(str(proof_kind))
        )
    except (TypeError, ValueError):
        return EvidenceCandidate.malformed(f"unusable_proof_kind:{proof_kind!r}")
    try:
        proof = BranchOwnershipProof(
            proof_id=str(proof_id),
            proof_kind=kind,
            trusted=trusted_value,
            reason=str(reason),
            source_block=_maybe_int(_field("source_block")),
            branch_arm=_maybe_int(_field("branch_arm")),
            source_state=_maybe_int(_field("source_state")),
            target_state=_maybe_int(_field("target_state")),
            target_entry=_maybe_int(_field("target_entry")),
            predicate_block=_maybe_int(_field("predicate_block")),
            dispatcher_entry_block=_maybe_int(_field("dispatcher_entry_block")),
            oracle_kind=_normalized_oracle_kind(_field("oracle_kind")),
            evidence=dict(_field("evidence") or {}),
            payload=dict(_field("payload") or {}),
            trust_provenance=trust_provenance,
        )
    except (TypeError, ValueError) as exc:
        return EvidenceCandidate.malformed(f"unusable_field:{exc}")
    return EvidenceCandidate.parsed(proof)


def branch_ownership_proof_from_any(
    value: object | None,
) -> BranchOwnershipProof | None:
    """Coerce an untyped ownership candidate into a proof, or ``None``.

    Convenience wrapper over :func:`branch_ownership_proof_candidate_from_any`
    for callers that do not distinguish "absent" from "malformed".  A consumer
    that may fall through to weaker evidence must use the tri-state instead.

    Coercion never registers a producer: whatever ``oracle_kind`` the input
    claims, the returned proof carries no registration token, so it cannot mint
    semantic-bridge or nonsemantic-rewrite authority.  A caller that genuinely
    vouches for the producer binds the row through
    :func:`branch_ownership_registration_authority`.
    """
    return branch_ownership_proof_candidate_from_any(value).value


def collect_branch_ownership_proofs(
    *,
    dag: object,
    dispatch_map: StateDispatcherMap | None = None,
    dispatcher_entry_block: int | None = None,
    trusted_opaque_provenance_kinds: frozenset[str] = (TRUSTED_OPAQUE_PROVENANCE_KINDS),
    proof_refiner: (
        Callable[
            [BranchOwnershipProof, object],
            BranchOwnershipProof | None,
        ]
        | None
    ) = None,
) -> tuple[BranchOwnershipProof, ...]:
    """Collect diagnostics-only ownership proofs for conditional DAG edges.

    First slice: classify only evidence that is already explicit and cheap:
    trusted opaque/BCF provenance, terminal return frontier edges, equivalent
    conditional arms, and unresolved arms.  Future MopTracker/Z3/native oracles
    should add stronger producers here without changing cfg/hexrays layers.
    """
    registrar = branch_ownership_registration_authority()
    edges = tuple(getattr(dag, "edges", ()) or ())
    conditional_edges: list[tuple[int, object]] = []
    outgoing_by_source: dict[int, list[object]] = {}
    for edge_index, edge in enumerate(edges):
        source_state = _edge_state(getattr(edge, "source_key", None))
        if source_state is not None:
            outgoing_by_source.setdefault(source_state, []).append(edge)
        if _edge_kind_name(edge) in {
            "CONDITIONAL_TRANSITION",
            "CONDITIONAL_RETURN",
            "EXIT_ROUTINE",
        }:
            conditional_edges.append((edge_index, edge))

    dispatcher_entry = dispatcher_entry_block
    if dispatcher_entry is None and dispatch_map is not None:
        dispatcher_entry = int(dispatch_map.dispatcher_entry_block)

    proofs: list[BranchOwnershipProof] = []
    for edge_index, edge in conditional_edges:
        source_state = _edge_state(getattr(edge, "source_key", None))
        target_state = _edge_state(getattr(edge, "target_key", None))
        source_block = _source_anchor_int(edge, "block_serial")
        branch_arm = _source_anchor_int(edge, "branch_arm")
        target_entry = _maybe_int(getattr(edge, "target_entry_anchor", None))
        edge_kind = _edge_kind_name(edge)
        provenance_kind = _edge_provenance_kind(edge)
        proof_kind = BranchOwnershipProofKind.UNRESOLVED
        trusted = False
        reason = "branch_ownership_unresolved"
        oracle_kind: BranchOwnershipOracleKind | str = (
            BranchOwnershipOracleKind.UNRESOLVED
        )

        if provenance_kind in trusted_opaque_provenance_kinds:
            proof_kind = BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM
            trusted = True
            reason = f"trusted_opaque_branch_provenance:{provenance_kind}"
            oracle_kind = BranchOwnershipOracleKind.EXPLICIT_OPAQUE_PROVENANCE
        elif edge_kind in {"CONDITIONAL_RETURN", "EXIT_ROUTINE"}:
            proof_kind = BranchOwnershipProofKind.TERMINAL_RETURN_FRONTIER
            trusted = True
            reason = "edge_kind_terminal_return_frontier"
            oracle_kind = BranchOwnershipOracleKind.DAG_TERMINAL_FRONTIER
        elif _target_state_has_terminal_frontier(
            edge,
            outgoing_by_source.get(target_state, ()),
        ):
            proof_kind = BranchOwnershipProofKind.TERMINAL_RETURN_FRONTIER
            trusted = True
            reason = "target_state_terminal_return_frontier"
            oracle_kind = BranchOwnershipOracleKind.DAG_TERMINAL_FRONTIER
        elif _has_equivalent_conditional_arm(
            edge,
            outgoing_by_source.get(source_state, ()),
        ):
            proof_kind = BranchOwnershipProofKind.EQUIVALENT_STATE_ARMS
            trusted = True
            reason = "conditional_arms_share_target_state"
            oracle_kind = BranchOwnershipOracleKind.DAG_EDGE_EQUIVALENCE

        proof = BranchOwnershipProof(
            proof_id=_proof_id(
                edge_index=edge_index,
                source_block=source_block,
                branch_arm=branch_arm,
                source_state=source_state,
                target_state=target_state,
                target_entry=target_entry,
            ),
            proof_kind=proof_kind,
            trusted=trusted,
            reason=reason,
            source_block=source_block,
            branch_arm=branch_arm,
            source_state=source_state,
            target_state=target_state,
            target_entry=target_entry,
            predicate_block=source_block,
            dispatcher_entry_block=dispatcher_entry,
            oracle_kind=oracle_kind,
            evidence={
                "edge_index": edge_index,
                "edge_kind": edge_kind,
                "provenance_kind": provenance_kind,
                "outgoing_count": len(outgoing_by_source.get(source_state, ())),
            },
        )
        proof = registrar.bind(proof, registrar.producer(oracle_kind))
        if proof_refiner is not None:
            proof = proof_refiner(proof, edge) or proof
        proofs.append(proof)
    return _append_terminal_selector_backedge_residue_proofs(
        edges=edges,
        proofs=tuple(proofs),
    )


def _append_terminal_selector_backedge_residue_proofs(
    *,
    edges: tuple[object, ...],
    proofs: tuple[BranchOwnershipProof, ...],
) -> tuple[BranchOwnershipProof, ...]:
    """Add proof rows for a narrow opaque terminal-selector backedge.

    A path-constant predicate proves only which arm the obfuscated selector
    chooses.  It does not prove the chosen arm can be removed.  This helper adds
    a separate rewrite-authorizing proof only for the stricter terminal pattern:

    - selector -> payload is a trusted opaque selected arm;
    - payload has a single outgoing transition back to the selector;
    - selector has a trusted terminal-frontier sibling;
    - payload is not reached from any other state; and
    - no same-edge proof marks the arm real data-dependent.

    The CFG consumer still has to prove source ownership or lower through a
    split/clone plan before mutating the raw graph.
    """

    outgoing_by_source: dict[int, list[object]] = {}
    incoming_by_target: dict[int, list[object]] = {}
    for edge in edges:
        source_state = _edge_state(getattr(edge, "source_key", None))
        target_state = _edge_state(getattr(edge, "target_key", None))
        if source_state is not None:
            outgoing_by_source.setdefault(source_state, []).append(edge)
        if target_state is not None:
            incoming_by_target.setdefault(target_state, []).append(edge)

    registrar = branch_ownership_registration_authority()
    backedge_producer = registrar.producer(
        BranchOwnershipOracleKind.TERMINAL_SELECTOR_BACKEDGE
    )
    added: list[BranchOwnershipProof] = []
    for proof in proofs:
        if not _is_opaque_selected_arm_proof(proof):
            continue
        source_state = proof.source_state
        target_state = proof.target_state
        if source_state is None or target_state is None:
            continue
        if any(
            _same_branch_edge_proof(existing, proof)
            and existing.authorizes_semantic_branch_bridge
            for existing in proofs
        ):
            continue
        if any(
            _same_branch_edge_proof(existing, proof)
            and existing.authorizes_nonsemantic_branch_rewrite
            for existing in proofs
        ):
            continue

        terminal_frontiers = tuple(
            existing
            for existing in proofs
            if (
                existing.has_registered_trust
                and existing.source_state == source_state
                and existing.proof_kind_name
                == BranchOwnershipProofKind.TERMINAL_RETURN_FRONTIER.value
            )
        )
        if not terminal_frontiers:
            continue

        target_outgoing = tuple(outgoing_by_source.get(target_state, ()))
        if len(target_outgoing) != 1:
            continue
        if _edge_state(getattr(target_outgoing[0], "target_key", None)) != source_state:
            continue

        target_incoming = tuple(incoming_by_target.get(target_state, ()))
        incoming_sources = {
            _edge_state(getattr(edge, "source_key", None)) for edge in target_incoming
        }
        evidence = dict(proof.evidence)
        evidence.update(
            {
                "opaque_selected_proof_id": proof.proof_id,
                "terminal_frontier_proof_ids": tuple(
                    terminal.proof_id for terminal in terminal_frontiers
                ),
                "payload_backedge_source_state": int(target_state) & _MASK64,
                "payload_backedge_target_state": int(source_state) & _MASK64,
                "payload_incoming_count": len(target_incoming),
                "payload_outgoing_count": len(target_outgoing),
            }
        )
        external_incoming_edges = tuple(
            edge
            for edge in target_incoming
            if not _proof_matches_edge_identity(proof, edge)
        )
        external_residue_proofs: list[BranchOwnershipProof] = []
        external_semantic_proofs: list[BranchOwnershipProof] = []
        external_materialization_veto_proofs: list[BranchOwnershipProof] = []
        unproven_external_edges = 0
        for incoming_edge in external_incoming_edges:
            matching_proofs = tuple(
                existing
                for existing in proofs
                if _proof_matches_edge_identity(existing, incoming_edge)
            )
            semantic_proofs = tuple(
                existing
                for existing in matching_proofs
                if existing.authorizes_semantic_branch_bridge
            )
            if semantic_proofs:
                external_semantic_proofs.extend(semantic_proofs)
                continue
            residue_proofs = tuple(
                existing
                for existing in matching_proofs
                if existing.authorizes_nonsemantic_branch_rewrite
            )
            if residue_proofs:
                external_residue_proofs.extend(residue_proofs)
                continue
            materialization_veto_proofs = tuple(
                existing
                for existing in matching_proofs
                if existing.vetoes_fallback_refinement
            )
            if materialization_veto_proofs:
                external_materialization_veto_proofs.extend(materialization_veto_proofs)
                continue
            else:
                unproven_external_edges += 1
                continue

        if (
            None in incoming_sources
            or external_semantic_proofs
            or external_materialization_veto_proofs
            or unproven_external_edges
        ):
            evidence["payload_incoming_source_states"] = tuple(
                _hex_state(source)
                for source in sorted(
                    source for source in incoming_sources if source is not None
                )
            )
            evidence["external_incoming_residue_proof_ids"] = tuple(
                proof.proof_id for proof in external_residue_proofs
            )
            evidence["external_incoming_semantic_proof_ids"] = tuple(
                proof.proof_id for proof in external_semantic_proofs
            )
            evidence["external_incoming_materialization_veto_proof_ids"] = tuple(
                proof.proof_id for proof in external_materialization_veto_proofs
            )
            side_effect_guard_reasons = tuple(
                str(proof.evidence.get("side_effect_guard_reason"))
                for proof in external_materialization_veto_proofs
                if proof.evidence.get("side_effect_guard_reason") is not None
            )
            if side_effect_guard_reasons:
                evidence["external_incoming_side_effect_guard_reasons"] = (
                    side_effect_guard_reasons
                )
                evidence["requires_side_effect_materialization"] = True
            evidence["unproven_external_incoming_edges"] = unproven_external_edges
            reason = "terminal_selector_backedge_payload_not_private"
            if (
                external_materialization_veto_proofs
                and not external_semantic_proofs
                and not unproven_external_edges
                and None not in incoming_sources
            ):
                reason = (
                    "terminal_selector_backedge_requires_side_effect_materialization"
                )
            blocked = BranchOwnershipProof(
                proof_id=f"{proof.proof_id}:terminal_selector_backedge_blocked",
                proof_kind=BranchOwnershipProofKind.UNRESOLVED,
                trusted=False,
                reason=reason,
                source_block=proof.source_block,
                branch_arm=proof.branch_arm,
                source_state=proof.source_state,
                target_state=proof.target_state,
                target_entry=proof.target_entry,
                predicate_block=proof.predicate_block,
                dispatcher_entry_block=proof.dispatcher_entry_block,
                oracle_kind=BranchOwnershipOracleKind.TERMINAL_SELECTOR_BACKEDGE,
                evidence=evidence,
                payload=dict(proof.payload),
            )
            added.append(registrar.bind(blocked, backedge_producer))
            continue

        if external_residue_proofs:
            evidence["payload_private_to_selector"] = False
            evidence["requires_cfg_split"] = True
            evidence["external_incoming_residue_proof_ids"] = tuple(
                proof.proof_id for proof in external_residue_proofs
            )
            external_incoming_sources = {
                _edge_state(getattr(edge, "source_key", None))
                for edge in external_incoming_edges
            }
            evidence["payload_incoming_source_states"] = tuple(
                _hex_state(source)
                for source in sorted(
                    source for source in external_incoming_sources if source is not None
                )
            )
        else:
            evidence["payload_private_to_selector"] = True
            evidence["requires_cfg_split"] = False

        residue = BranchOwnershipProof(
            proof_id=f"{proof.proof_id}:terminal_selector_backedge_residue",
            proof_kind=BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM,
            trusted=True,
            reason="opaque_selected_terminal_selector_backedge_residue",
            source_block=proof.source_block,
            branch_arm=proof.branch_arm,
            source_state=proof.source_state,
            target_state=proof.target_state,
            target_entry=proof.target_entry,
            predicate_block=proof.predicate_block,
            dispatcher_entry_block=proof.dispatcher_entry_block,
            oracle_kind=BranchOwnershipOracleKind.TERMINAL_SELECTOR_BACKEDGE,
            evidence=evidence,
            payload=dict(proof.payload),
        )
        added.append(registrar.bind(residue, backedge_producer))

    if not added:
        return proofs
    return (*proofs, *tuple(added))


def _is_opaque_selected_arm_proof(proof: BranchOwnershipProof) -> bool:
    if not proof.has_registered_trust:
        return False
    return proof.proof_kind_name in {
        BranchOwnershipProofKind.OPAQUE_ALWAYS_TRUE.value,
        BranchOwnershipProofKind.OPAQUE_ALWAYS_FALSE.value,
    }


def _same_branch_edge_proof(
    left: BranchOwnershipProof,
    right: BranchOwnershipProof,
) -> bool:
    return (
        left.source_state == right.source_state
        and left.target_state == right.target_state
        and left.branch_arm == right.branch_arm
        and left.target_entry == right.target_entry
    )


def _proof_matches_edge_identity(
    proof: BranchOwnershipProof,
    edge: object,
) -> bool:
    edge_source_block = _source_anchor_int(edge, "block_serial")
    edge_branch_arm = _source_anchor_int(edge, "branch_arm")
    edge_source_state = _edge_state(getattr(edge, "source_key", None))
    edge_target_state = _edge_state(getattr(edge, "target_key", None))
    edge_target_entry = _maybe_int(getattr(edge, "target_entry_anchor", None))
    if (
        proof.source_block is None
        or proof.branch_arm is None
        or proof.source_state is None
        or proof.target_state is None
        or proof.target_entry is None
        or edge_source_block is None
        or edge_branch_arm is None
        or edge_source_state is None
        or edge_target_state is None
        or edge_target_entry is None
    ):
        return False
    return (
        proof.source_block == edge_source_block
        and proof.branch_arm == edge_branch_arm
        and proof.source_state == edge_source_state
        and proof.target_state == edge_target_state
        and proof.target_entry == edge_target_entry
    )


def _proof_id(
    *,
    edge_index: int,
    source_block: int | None,
    branch_arm: int | None,
    source_state: int | None,
    target_state: int | None,
    target_entry: int | None,
) -> str:
    return (
        f"branch_ownership:edge={edge_index}:"
        f"src_blk={source_block}:arm={branch_arm}:"
        f"src_state={_hex_state(source_state)}:"
        f"target_state={_hex_state(target_state)}:"
        f"target_entry={target_entry}"
    )


def _edge_kind_name(edge: object) -> str:
    kind = getattr(edge, "kind", None)
    name = getattr(kind, "name", None)
    return str(name if name is not None else kind)


def _edge_state(key: object | None) -> int | None:
    if key is None:
        return None
    state = getattr(key, "state_const", None)
    if state is None:
        return None
    try:
        return int(state) & _MASK64
    except (TypeError, ValueError):
        return None


def _source_anchor_int(edge: object, attr: str) -> int | None:
    anchor = getattr(edge, "source_anchor", None)
    if anchor is None:
        return None
    return _maybe_int(getattr(anchor, attr, None))


def _edge_provenance_kind(edge: object) -> str | None:
    candidates = [
        getattr(edge, "opaque_branch_provenance_kind", None),
        getattr(edge, "provenance_kind", None),
    ]
    metadata = getattr(edge, "metadata", None)
    if isinstance(metadata, dict):
        candidates.extend(
            (
                metadata.get("opaque_branch_provenance_kind"),
                metadata.get("provenance_kind"),
            )
        )
    source_anchor = getattr(edge, "source_anchor", None)
    if source_anchor is not None:
        candidates.extend(
            (
                getattr(source_anchor, "opaque_branch_provenance_kind", None),
                getattr(source_anchor, "provenance_kind", None),
            )
        )
    for candidate in candidates:
        if candidate is not None:
            return str(candidate)
    return None


def _has_equivalent_conditional_arm(
    edge: object,
    siblings: list[object] | tuple[object, ...],
) -> bool:
    target_state = _edge_state(getattr(edge, "target_key", None))
    if target_state is None:
        return False
    equivalent_count = 0
    for sibling in siblings:
        if _edge_kind_name(sibling) != "CONDITIONAL_TRANSITION":
            continue
        if _edge_state(getattr(sibling, "target_key", None)) == target_state:
            equivalent_count += 1
    return equivalent_count > 1


def _target_state_has_terminal_frontier(
    edge: object,
    target_outgoing: list[object] | tuple[object, ...],
) -> bool:
    if _edge_kind_name(edge) != "CONDITIONAL_TRANSITION":
        return False
    target_state = _edge_state(getattr(edge, "target_key", None))
    if target_state is None:
        return False
    return any(
        _edge_kind_name(outgoing) in {"CONDITIONAL_RETURN", "EXIT_ROUTINE"}
        for outgoing in target_outgoing
    )


def _maybe_int(value: object | None) -> int | None:
    if value is None:
        return None
    try:
        if isinstance(value, str):
            return int(value, 0)
        return int(value)
    except (TypeError, ValueError):
        return None


def _hex_state(value: int | None) -> str | None:
    if value is None:
        return None
    return f"0x{int(value) & _MASK64:016x}"


def proof_json(value: object) -> str:
    """Stable JSON helper for debugging/tests."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


__all__ = [
    "UNSPECIFIED_BRANCH_OWNERSHIP_ORACLE",
    "BranchOwnershipAuthority",
    "BranchOwnershipEvidenceKey",
    "BranchOwnershipOracleKind",
    "BranchOwnershipProducerRegistration",
    "BranchOwnershipProof",
    "BranchOwnershipProofKind",
    "BranchOwnershipRegistrationAuthority",
    "BranchOwnershipTrustProvenance",
    "TRUSTED_OPAQUE_PROVENANCE_KINDS",
    "branch_ownership_proof_candidate_from_any",
    "branch_ownership_proof_from_any",
    "branch_ownership_registration_authority",
    "collect_branch_ownership_proofs",
    "registered_branch_ownership_proof",
    "proof_json",
]
