"""Trust decisions for state-machine transition evidence.

This module is the boundary between transition producers and consumers that
may turn evidence into concrete DAG/CFG authority.  Producers can attach typed
trust evidence directly; older producers that only expose provenance strings
are adapted here so consumers do not grow local allowlists.

Provenance discipline (d81-9q6e)
--------------------------------
The typed adapter below is consulted *before* the branch-ownership adapter, so
it is the first thing the production gate
(``linearized_state_dag._is_supported_explicit_conditional_transition``) sees.
It therefore carries the same two fail-closed gates ``branch_ownership`` does:

``trusted`` must be a real ``bool``
    ``bool(value)`` used to launder the string ``"false"`` -- and any other
    non-empty string, or ``1`` -- into a trusted row.  A non-boolean trust
    value is now recorded as :attr:`TransitionTrustProvenance.MALFORMED`; the
    row keeps ``trusted=False`` and authorizes nothing.

the producer must be vouched for
    An absent ``trust_kind`` used to default to
    :attr:`TransitionTrustKind.EXPLICIT_PRODUCER_TRUST`, a bridge-authorising
    kind, and nothing ever asked *which* producer minted the row.  A grant now
    requires a producer that is either enumerated in
    :class:`TransitionTrustProducerKind` (the in-tree adapters) or named by the
    caller in ``adapted_producers=`` at the boundary.  Vouching is per call, not
    process-global state a stray import could extend.
"""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass, field, replace
from enum import Enum

from d810.analyses.control_flow.branch_ownership import (
    BranchOwnershipAuthority,
    branch_ownership_proof_from_any,
)
from d810.analyses.control_flow.dispatch_key import (
    DispatchKeyTransformKind,
    dispatch_key_transform_kind_from_any,
)

#: Producer name carried by a row that never named one.  Deliberately not a
#: member of :class:`TransitionTrustProducerKind`: an absent producer is
#: unregistered, never a registered default.
UNSPECIFIED_TRANSITION_TRUST_PRODUCER = "unspecified_producer"


class TransitionTrustKind(str, Enum):
    "Typed source of authority for promoting transition evidence.\n\n    ``DYNAMIC_STATE_WRITE``\n        A preanalysis producer observed a conditional state write through the\n        dispatcher state variable or a global/state alias with enough evidence\n        to treat the written state as the branch target.  This can authorize an\n        explicit conditional DAG bridge because it identifies real transition\n        data, not merely graph shape.\n\n    ``BRANCH_OWNERSHIP_REAL_DATA_DEPENDENT``\n        Branch ownership proved the arm is real source-program control flow.\n        This is the only branch-ownership proof kind that becomes semantic DAG\n        bridge authority.  Nonsemantic ownership kinds remain rewrite evidence.\n\n    ``EXPLICIT_PRODUCER_TRUST``\n        A future oracle, for example MopTracker or Z3, attached a typed trust\n        result directly.  Use this only when the producer already performed the\n        semantic-vs-obfuscation distinction and can explain it in ``reason`` /\n        ``evidence``.\n\n    ``UNSUPPORTED``\n        The transition is diagnostic-only for this consumer.  No explicit\n        conditional bridge should be built from it.\n"

    DYNAMIC_STATE_WRITE = "DYNAMIC_STATE_WRITE"
    BRANCH_OWNERSHIP_REAL_DATA_DEPENDENT = "BRANCH_OWNERSHIP_REAL_DATA_DEPENDENT"
    EXPLICIT_PRODUCER_TRUST = "EXPLICIT_PRODUCER_TRUST"
    UNSUPPORTED = "UNSUPPORTED"


class TransitionTrustProducerKind(str, Enum):
    """Which producer minted a :class:`TransitionTrustResult`.

    Only the two in-tree adapters are enumerated, because they are the only
    producers this module ships.  An out-of-tree oracle is vouched for per
    call via ``adapted_producers=`` rather than by being invented here.
    """

    BRANCH_OWNERSHIP_ADAPTER = "branch_ownership_adapter"
    PROVENANCE_TAG_ADAPTER = "provenance_tag_adapter"


class TransitionTrustProducerRegistration(str, Enum):
    """Whether the producer that minted a row is vouched for at all.

    ``REGISTERED``
        ``producer`` names an in-tree adapter enumerated in
        :class:`TransitionTrustProducerKind`.

    ``EXPLICITLY_ADAPTED``
        An out-of-tree producer name the *caller* vouched for by passing it in
        ``adapted_producers`` at this boundary.

    ``UNKNOWN``
        Nobody vouched for the producer.  The row is still carried as evidence,
        but it may not authorize an explicit conditional bridge.
    """

    REGISTERED = "registered"
    EXPLICITLY_ADAPTED = "explicitly_adapted"
    UNKNOWN = "unknown"


class TransitionTrustProvenance(str, Enum):
    """Whether the row's trust value was a real boolean decision."""

    WELL_FORMED = "well_formed"
    MALFORMED = "malformed"


class TransitionTrustAuthority(str, Enum):
    """The single typed verdict a trust row carries.

    ``EXPLICIT_CONDITIONAL_BRIDGE``
        The row may become explicit conditional DAG input.

    ``DIAGNOSTIC_ONLY``
        Evidence, not permission.  Untrusted rows and non-bridge kinds land
        here.

    ``UNRESOLVED_PROVENANCE``
        The row could not be trusted to *mean* anything: its trust value was
        not a boolean, or the producer that minted it is unregistered and
        nobody adapted it.  Deliberately distinct from ``DIAGNOSTIC_ONLY`` so a
        consumer can refuse it loudly instead of silently treating malformed
        provenance as ordinary evidence.
    """

    EXPLICIT_CONDITIONAL_BRIDGE = "explicit_conditional_bridge"
    DIAGNOSTIC_ONLY = "diagnostic_only"
    UNRESOLVED_PROVENANCE = "unresolved_provenance"


def _enum_value(value: object) -> str:
    """Render an enum member as its value, anything else via ``str``.

    ``str(SomeStrEnum.MEMBER)`` returns ``"SomeStrEnum.MEMBER"``, not the
    value, so a plain ``str()`` coercion would corrupt a serialized row the
    moment a producer switched from a literal to a member.
    """
    if isinstance(value, Enum):
        return str(value.value)
    return str(value)


#: Trust kinds that can authorize an explicit conditional bridge.  Every one of
#: them is a *grant*, so every one of them is gated on producer registration.
_BRIDGE_TRUST_KIND_NAMES = frozenset(
    {
        TransitionTrustKind.DYNAMIC_STATE_WRITE.value,
        TransitionTrustKind.BRANCH_OWNERSHIP_REAL_DATA_DEPENDENT.value,
        TransitionTrustKind.EXPLICIT_PRODUCER_TRUST.value,
    }
)


@dataclass(frozen=True, slots=True)
class TransitionTrustResult:
    """Decision describing whether transition evidence can authorize a use."""

    trusted: bool
    reason: str
    trust_kind: TransitionTrustKind | str = TransitionTrustKind.UNSUPPORTED
    provenance_kind: str | None = None
    dispatch_key_transform_kind: DispatchKeyTransformKind | None = None
    evidence: dict[str, object] = field(default_factory=dict)
    producer: TransitionTrustProducerKind | str = UNSPECIFIED_TRANSITION_TRUST_PRODUCER
    adapted_producer: bool = False
    trust_provenance: TransitionTrustProvenance = TransitionTrustProvenance.WELL_FORMED

    def __post_init__(self) -> None:
        """Refuse a non-boolean trust decision at construction time.

        In-tree producers pass a real ``bool``; anything else is a provenance
        bug that used to be laundered into a trusted row by ``bool(value)``.
        Duck-typed rows from outside the tree are not constructed directly:
        they go through :func:`transition_trust_result_from_any`, which records
        an explicit ``MALFORMED`` verdict rather than raising.
        """
        if not isinstance(self.trusted, bool):
            raise TypeError(
                "TransitionTrustResult.trusted must be a bool, got "
                f"{type(self.trusted).__name__!r} ({self.trusted!r}); "
                "use transition_trust_result_from_any() for untyped input"
            )
        if not isinstance(self.adapted_producer, bool):
            raise TypeError(
                "TransitionTrustResult.adapted_producer must be a bool, got "
                f"{type(self.adapted_producer).__name__!r}"
            )

    @property
    def trust_kind_name(self) -> str:
        kind = self.trust_kind
        if isinstance(kind, TransitionTrustKind):
            return kind.value
        return str(kind)

    @property
    def producer_name(self) -> str:
        """The producer name as a plain ``str``, whatever the field holds."""
        return _enum_value(self.producer)

    @property
    def is_known_producer(self) -> bool:
        """Whether this row names an adapter enumerated in this module."""
        try:
            TransitionTrustProducerKind(self.producer_name)
        except ValueError:
            return False
        return True

    @property
    def producer_registration(self) -> TransitionTrustProducerRegistration:
        """Who, if anyone, vouches for the producer that minted this row."""
        if self.is_known_producer:
            return TransitionTrustProducerRegistration.REGISTERED
        if self.adapted_producer:
            return TransitionTrustProducerRegistration.EXPLICITLY_ADAPTED
        return TransitionTrustProducerRegistration.UNKNOWN

    @property
    def authority(self) -> TransitionTrustAuthority:
        """What this row permits, as one typed verdict.

        Two provenance gates sit in front of the grant verdict:

        * a row whose trust value was not a boolean is
          ``UNRESOLVED_PROVENANCE``, whatever kind it claims to be;
        * a bridge grant requires a producer that is registered or explicitly
          adapted.  An unvouched producer abstains rather than granting.

        Registration gates *grants* only: an unvouched producer's untrusted or
        non-bridge row stays ``DIAGNOSTIC_ONLY``, because reclassifying
        evidence would lose information without making anything safer.
        """
        if self.trust_provenance is not TransitionTrustProvenance.WELL_FORMED:
            return TransitionTrustAuthority.UNRESOLVED_PROVENANCE
        if not self.trusted:
            return TransitionTrustAuthority.DIAGNOSTIC_ONLY
        if self.trust_kind_name not in _BRIDGE_TRUST_KIND_NAMES:
            return TransitionTrustAuthority.DIAGNOSTIC_ONLY
        if self.producer_registration is TransitionTrustProducerRegistration.UNKNOWN:
            return TransitionTrustAuthority.UNRESOLVED_PROVENANCE
        return TransitionTrustAuthority.EXPLICIT_CONDITIONAL_BRIDGE

    @property
    def authorizes_explicit_conditional_bridge(self) -> bool:
        """Whether this trust result can become explicit conditional DAG input."""

        return self.authority is TransitionTrustAuthority.EXPLICIT_CONDITIONAL_BRIDGE


_PROVENANCE_TAG_TRUST_KIND_BY_NAME = {
    "global_or_state_write": TransitionTrustKind.DYNAMIC_STATE_WRITE,
}

_PROVENANCE_TAG_REASON_BY_KIND = {
    TransitionTrustKind.DYNAMIC_STATE_WRITE: "dynamic_state_write",
}

_DISPATCH_KEY_TRANSFORM_BY_PROVENANCE_KIND = {
    "derived_xor_dispatch_key": DispatchKeyTransformKind.XOR,
}


def classify_transition_trust_for_explicit_conditional_bridge(
    transition: object,
    *,
    adapted_producers: Collection[str] = (),
) -> TransitionTrustResult:
    """Classify whether a conditional transition may form an explicit bridge.

    The result is intentionally conservative: diagnostic provenance is not
    enough.  A producer must either attach typed trust evidence, attach a
    trusted branch-ownership proof for real data-dependent control, or expose
    a recognized provenance tag adapted at this boundary.

    ``adapted_producers`` names out-of-tree producers the caller vouches for.
    A typed row minted by any other unregistered producer cannot grant.
    """

    if not bool(getattr(transition, "is_conditional", False)):
        return TransitionTrustResult(False, "not_conditional")
    if not bool(getattr(transition, "provenance_chain", ())):
        return TransitionTrustResult(False, "missing_provenance_chain")

    typed_result = _typed_transition_trust_result(
        transition,
        adapted_producers=adapted_producers,
    )
    if typed_result is not None:
        return typed_result

    branch_result = _branch_ownership_transition_trust_result(transition)
    if branch_result is not None:
        return branch_result

    provenance_kind = _transition_provenance_kind(transition)
    dispatch_key_transform_kind = _transition_dispatch_key_transform_kind(
        transition,
        provenance_kind=provenance_kind,
    )
    provenance_trust_kind = _PROVENANCE_TAG_TRUST_KIND_BY_NAME.get(provenance_kind)
    if provenance_trust_kind is not None:
        return TransitionTrustResult(
            True,
            _PROVENANCE_TAG_REASON_BY_KIND[provenance_trust_kind],
            trust_kind=provenance_trust_kind,
            provenance_kind=provenance_kind,
            dispatch_key_transform_kind=dispatch_key_transform_kind,
            evidence={"source": "provenance_tag_adapter"},
            producer=TransitionTrustProducerKind.PROVENANCE_TAG_ADAPTER,
        )

    if dispatch_key_transform_kind is not None:
        return TransitionTrustResult(
            False,
            "dispatch_key_transform_not_authority",
            provenance_kind=provenance_kind,
            dispatch_key_transform_kind=dispatch_key_transform_kind,
            evidence={"source": "dispatch_key_transform_adapter"},
        )

    return TransitionTrustResult(
        False,
        "unsupported_provenance",
        provenance_kind=provenance_kind,
    )


def transition_is_trusted_for_explicit_conditional_bridge(
    transition: object,
    *,
    adapted_producers: Collection[str] = (),
) -> bool:
    """Return whether transition evidence can authorize explicit bridging."""

    return classify_transition_trust_for_explicit_conditional_bridge(
        transition,
        adapted_producers=adapted_producers,
    ).authorizes_explicit_conditional_bridge


def _typed_transition_trust_result(
    transition: object,
    *,
    adapted_producers: Collection[str] = (),
) -> TransitionTrustResult | None:
    """Adapt a typed trust attribute into a transition trust decision.

    A row whose provenance did not resolve -- a non-boolean trust value, or an
    unvouched producer claiming bridge authority -- is refused here with an
    explicit reason.  It is deliberately not skipped: falling through would let
    a weaker evidence source (branch ownership, or a provenance tag) answer for
    a row that arrived malformed.
    """
    for value in _typed_trust_candidates(transition):
        result = transition_trust_result_from_any(
            value,
            adapted_producers=adapted_producers,
        )
        if result is None:
            continue
        if result.authority is TransitionTrustAuthority.UNRESOLVED_PROVENANCE:
            return TransitionTrustResult(
                False,
                f"transition_trust_unresolved_provenance:{result.trust_kind_name}",
                provenance_kind=result.provenance_kind,
                dispatch_key_transform_kind=result.dispatch_key_transform_kind,
                evidence={
                    "producer": result.producer_name,
                    "producer_registration": result.producer_registration.value,
                    "trust_provenance": result.trust_provenance.value,
                },
            )
        return result
    return None


def _typed_trust_candidates(transition: object) -> tuple[object, ...]:
    candidates: list[object] = []
    for attr in ("transition_trust", "trust_result", "trust_evidence"):
        value = getattr(transition, attr, None)
        if value is not None:
            candidates.append(value)
    metadata = getattr(transition, "metadata", None)
    if isinstance(metadata, dict):
        for key in ("transition_trust", "trust_result", "trust_evidence"):
            value = metadata.get(key)
            if value is not None:
                candidates.append(value)
    return tuple(candidates)


def _normalized_producer(value: object) -> TransitionTrustProducerKind | str:
    """Coerce a producer name to a member when recognised, else keep it.

    An absent or empty producer name resolves to
    :data:`UNSPECIFIED_TRANSITION_TRUST_PRODUCER`, which is *not* an enumerated
    member, so it is unregistered and cannot grant.
    """
    if isinstance(value, TransitionTrustProducerKind):
        return value
    if value is None or value == "":
        return UNSPECIFIED_TRANSITION_TRUST_PRODUCER
    name = _enum_value(value)
    try:
        return TransitionTrustProducerKind(name)
    except ValueError:
        return name


def transition_trust_result_from_any(
    value: object | None,
    *,
    adapted_producers: Collection[str] = (),
) -> TransitionTrustResult | None:
    """Coerce a typed trust object/dict into ``TransitionTrustResult``.

    The input is untyped by design, so this is the boundary where provenance is
    checked rather than assumed:

    ``trusted``
        Must be a real ``bool``.  ``"true"``, ``"false"``, ``1``, ``0`` are
        *not* coerced; the row is returned with ``trusted=False`` and
        :attr:`TransitionTrustProvenance.MALFORMED`, so it authorizes nothing
        and a consumer can say why.

    ``trust_kind``
        An absent kind is :attr:`TransitionTrustKind.UNSUPPORTED`, never a
        bridge-authorising default.

    ``adapted_producers``
        Producer names the caller explicitly vouches for.  A row whose
        ``producer`` is neither an enumerated
        :class:`TransitionTrustProducerKind` nor named here cannot authorize an
        explicit conditional bridge.
    """

    if value is None:
        return None
    adapted = frozenset(str(name) for name in adapted_producers)
    if isinstance(value, TransitionTrustResult):
        if (
            adapted
            and not value.adapted_producer
            and not value.is_known_producer
            and value.producer_name in adapted
        ):
            return replace(value, adapted_producer=True)
        return value
    if isinstance(value, dict):
        trusted = value.get("trusted")
        reason = value.get("reason")
        trust_kind = value.get("trust_kind")
        provenance_kind = value.get("provenance_kind")
        dispatch_key_transform_kind = value.get("dispatch_key_transform_kind")
        evidence = value.get("evidence") or {}
        producer = value.get("producer")
    else:
        trusted = getattr(value, "trusted", None)
        reason = getattr(value, "reason", None)
        trust_kind = getattr(value, "trust_kind", None)
        provenance_kind = getattr(value, "provenance_kind", None)
        dispatch_key_transform_kind = getattr(
            value,
            "dispatch_key_transform_kind",
            None,
        )
        evidence = getattr(value, "evidence", None) or {}
        producer = getattr(value, "producer", None)
    if trusted is None or reason is None:
        return None
    if isinstance(trusted, bool):
        trust_provenance = TransitionTrustProvenance.WELL_FORMED
        trusted_value = trusted
    else:
        trust_provenance = TransitionTrustProvenance.MALFORMED
        trusted_value = False
    if trust_kind is None:
        trust_kind = TransitionTrustKind.UNSUPPORTED
    try:
        normalized_kind = (
            trust_kind
            if isinstance(trust_kind, TransitionTrustKind)
            else TransitionTrustKind(str(trust_kind))
        )
    except ValueError:
        normalized_kind = str(trust_kind)
    normalized_producer = _normalized_producer(producer)
    return TransitionTrustResult(
        trusted_value,
        str(reason),
        trust_kind=normalized_kind,
        provenance_kind=(None if provenance_kind is None else str(provenance_kind)),
        dispatch_key_transform_kind=dispatch_key_transform_kind_from_any(
            dispatch_key_transform_kind
        ),
        evidence=dict(evidence),
        producer=normalized_producer,
        adapted_producer=(
            not isinstance(normalized_producer, TransitionTrustProducerKind)
            and _enum_value(normalized_producer) in adapted
        ),
        trust_provenance=trust_provenance,
    )


def _branch_ownership_transition_trust_result(
    transition: object,
) -> TransitionTrustResult | None:
    """Adapt a branch-ownership proof into a transition trust decision.

    A row whose provenance did not resolve -- a non-boolean trust value, or an
    unregistered producer claiming grant authority -- is refused here with an
    explicit reason.  It is deliberately not skipped: falling through would let
    a weaker evidence source answer for a row that arrived malformed.
    """
    for value in _branch_ownership_candidates(transition):
        proof = branch_ownership_proof_from_any(value)
        if proof is None:
            continue
        proof_kind = proof.proof_kind_name
        authority = proof.authority
        if authority is BranchOwnershipAuthority.SEMANTIC_BRIDGE:
            return TransitionTrustResult(
                True,
                "branch_ownership_real_data_dependent",
                trust_kind=(TransitionTrustKind.BRANCH_OWNERSHIP_REAL_DATA_DEPENDENT),
                evidence={
                    "proof_id": proof.proof_id,
                    "oracle_kind": proof.oracle_kind_name,
                },
                producer=TransitionTrustProducerKind.BRANCH_OWNERSHIP_ADAPTER,
            )
        if authority is BranchOwnershipAuthority.UNRESOLVED_PROVENANCE:
            return TransitionTrustResult(
                False,
                f"branch_ownership_unresolved_provenance:{proof_kind}",
                evidence={
                    "proof_id": proof.proof_id,
                    "trusted": proof.trusted,
                    "oracle_kind": proof.oracle_kind_name,
                    "producer_registration": proof.producer_registration.value,
                    "trust_provenance": proof.trust_provenance.value,
                },
            )
        return TransitionTrustResult(
            False,
            f"branch_ownership_not_bridge_authority:{proof_kind}",
            evidence={
                "proof_id": proof.proof_id,
                "trusted": proof.trusted,
                "oracle_kind": proof.oracle_kind_name,
            },
        )
    return None


def _branch_ownership_candidates(transition: object) -> tuple[object, ...]:
    candidates: list[object] = []
    for attr in ("branch_ownership_proof", "branch_ownership"):
        value = getattr(transition, attr, None)
        if value is not None:
            candidates.append(value)
    metadata = getattr(transition, "metadata", None)
    if isinstance(metadata, dict):
        for key in ("branch_ownership_proof", "branch_ownership"):
            value = metadata.get(key)
            if value is not None:
                candidates.append(value)
    return tuple(candidates)


def _transition_provenance_kind(transition: object) -> str | None:
    provenance_kind = getattr(transition, "provenance_kind", None)
    if provenance_kind is None:
        metadata = getattr(transition, "metadata", None)
        if isinstance(metadata, dict):
            provenance_kind = metadata.get("provenance_kind")
    return None if provenance_kind is None else str(provenance_kind)


def _transition_dispatch_key_transform_kind(
    transition: object,
    *,
    provenance_kind: str | None,
) -> DispatchKeyTransformKind | None:
    for attr in (
        "dispatch_key_transform_kind",
        "key_transform_kind",
        "dispatch_key_transform",
    ):
        result = dispatch_key_transform_kind_from_any(getattr(transition, attr, None))
        if result is not None:
            return result
    metadata = getattr(transition, "metadata", None)
    if isinstance(metadata, dict):
        for key in (
            "dispatch_key_transform_kind",
            "key_transform_kind",
            "dispatch_key_transform",
        ):
            result = dispatch_key_transform_kind_from_any(metadata.get(key))
            if result is not None:
                return result
    return _DISPATCH_KEY_TRANSFORM_BY_PROVENANCE_KIND.get(provenance_kind)


__all__ = [
    "UNSPECIFIED_TRANSITION_TRUST_PRODUCER",
    "TransitionTrustAuthority",
    "TransitionTrustKind",
    "TransitionTrustProducerKind",
    "TransitionTrustProducerRegistration",
    "TransitionTrustProvenance",
    "TransitionTrustResult",
    "classify_transition_trust_for_explicit_conditional_bridge",
    "transition_is_trusted_for_explicit_conditional_bridge",
    "transition_trust_result_from_any",
]
