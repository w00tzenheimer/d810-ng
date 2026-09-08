"""Authority-owned producer registration for proof rows.

A producer name written on an evidence row is a **claim**.  Rounds 1 and 2 of
the d81-9q6e audit gated grants on "producer registration", but registration
was still computed *from the row*: a foreign dict that named an enumerated
oracle was normalised to that member and reported ``REGISTERED``, and a
directly constructed record could set a producer-controlled boolean
(``adapted_producer=True``) and register itself.  Evidence authenticated its
own producer.

This module supplies the missing authority.  Registration is **minted**, never
claimed:

* :class:`ProducerIdentity` is an *object* a binder owns.  Identity, not name,
  is what the binder recognizes -- two identities with the same name are
  different producers.
* :class:`ProducerRegistrationAuthority` is created by the lifecycle/session
  (or by the authority module that owns the trust decision) over the producer
  identities it recognizes.  Its only way to produce a token is
  :meth:`~ProducerRegistrationAuthority.bind`, which refuses any object that is
  not one of *its own* identities.
* :class:`ProducerRegistrationToken` is a frozen record carrying a
  binder-private nonce.  It cannot be constructed without that nonce, so a row,
  a dict, or a hand-written constructor call cannot fabricate one.

Threat model, stated plainly: this defends the boundary where **data** crosses
into a trust decision.  Serialized rows, duck-typed objects and direct
constructions can never register themselves.  It does not, and cannot, defend
against arbitrary in-process code that imports this module's private names --
Python has no such boundary.  In-tree producers are code, and code is reviewed;
rows are data, and data is now unable to vouch for itself.

There is deliberately no module-global registry: an authority is a value the
caller owns for the duration of the work it authorizes.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from enum import Enum

from d810.core.typing import TypeVar

#: The producer name carried by a row that never named one.  It is not a
#: producer: absence can never be vouched for after the fact, so
#: :class:`ProducerIdentity` refuses to be built from it.
UNSPECIFIED_PRODUCER = "unspecified_producer"


class ProducerRegistration(str, Enum):
    """Who, if anyone, vouches for the producer that minted a row.

    ``REGISTERED``
        The binder recognizes the producer as one this codebase ships and
        reviews.

    ``EXPLICITLY_ADAPTED``
        An out-of-tree producer the *owner of the binder* vouched for when it
        built the binder, by handing it that producer's identity object.

    ``UNKNOWN``
        Nobody vouched.  The row is still carried as evidence, but it may not
        mint authority.  This is what every unbound row reports, including a
        row that claims a recognized producer name.
    """

    REGISTERED = "registered"
    EXPLICITLY_ADAPTED = "explicitly_adapted"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True, eq=False)
class ProducerIdentity:
    """One producer a binder recognizes, by object identity.

    ``eq=False`` is load-bearing: identities compare by object identity, so a
    look-alike built elsewhere with the same ``name`` is a *different*
    producer and is refused by :meth:`ProducerRegistrationAuthority.bind`.

    ``record_value`` is what :meth:`ProducerRegistrationAuthority.bind` writes
    into the bound record's producer field, so an enum-backed producer keeps
    its typed member rather than degrading to a bare string.
    """

    name: str
    registration: ProducerRegistration = ProducerRegistration.REGISTERED
    record_value: object | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("ProducerIdentity requires a non-empty producer name")
        if self.name == UNSPECIFIED_PRODUCER:
            raise ValueError(
                "the unspecified producer sentinel is the absence of a producer; "
                "absence can never be vouched for after the fact"
            )
        if self.registration is ProducerRegistration.UNKNOWN:
            raise ValueError(
                "a ProducerIdentity is a vouched producer; UNKNOWN is the "
                "verdict for rows nobody vouched for, not a registration"
            )

    @property
    def value(self) -> object:
        """The value ``bind`` writes into the record's producer field."""
        return self.name if self.record_value is None else self.record_value


@dataclass(frozen=True, slots=True, eq=False)
class _AuthorityNonce:
    """A binder-private identity a record cannot fabricate.

    Module-private and only ever constructed inside
    :class:`ProducerRegistrationAuthority`.  ``eq=False`` means an equal-valued
    copy is still a different nonce, so a token is bound to the *instance* that
    minted it.
    """

    secret: bytes


@dataclass(frozen=True, slots=True, eq=False)
class ProducerRegistrationToken:
    """Unforgeable evidence that an authority bound a record to a producer.

    A record carries this instead of a producer-controlled boolean.  It cannot
    be constructed without an :class:`_AuthorityNonce`, which only an authority
    creates, so no row and no direct construction can mint one.
    """

    producer_name: str
    registration: ProducerRegistration
    #: The record family this token was minted for.  A token minted for a
    #: branch-ownership row does not register a transition-trust row, so an
    #: authority for one record family cannot silently vouch for another.
    domain: str
    nonce: _AuthorityNonce

    def __post_init__(self) -> None:
        if not isinstance(self.nonce, _AuthorityNonce):
            raise TypeError(
                "a ProducerRegistrationToken may only be minted by "
                "ProducerRegistrationAuthority.bind(); registration is minted, "
                "never claimed"
            )
        if self.registration is ProducerRegistration.UNKNOWN:
            raise ValueError("a minted token is never UNKNOWN")

    def is_minted_by(self, authority: ProducerRegistrationAuthority) -> bool:
        """Whether *this exact* authority instance minted the token."""
        return authority.owns_nonce(self.nonce)


RecordT = TypeVar("RecordT")


class ProducerRegistrationAuthority:
    """Binds a record to a producer this binder -- and only this binder -- owns.

    Subclasses name the record fields they bind, so a domain record keeps its
    own vocabulary (``oracle_kind`` for branch ownership, ``producer`` for
    transition trust) while the minting rule stays in one place.
    """

    #: The record family this binder mints for; tokens are scoped to it.
    RECORD_DOMAIN: str = "producer"
    #: The field on the bound record holding the producer name/member.
    RECORD_PRODUCER_FIELD: str = "producer"
    #: The field on the bound record holding the registration token.
    RECORD_REGISTRATION_FIELD: str = "registration"

    __slots__ = ("_identities", "_by_name", "_nonce")

    def __init__(self, producers: Iterable[ProducerIdentity]) -> None:
        identities: dict[int, ProducerIdentity] = {}
        by_name: dict[str, ProducerIdentity] = {}
        for producer in producers:
            if not isinstance(producer, ProducerIdentity):
                raise TypeError(
                    "a registration authority is built from ProducerIdentity "
                    f"objects, got {type(producer).__name__!r}"
                )
            if producer.name in by_name and by_name[producer.name] is not producer:
                raise ValueError(
                    f"two distinct identities claim the producer name "
                    f"{producer.name!r}; a name is a claim, so the binder "
                    "refuses to guess which object is meant"
                )
            identities[id(producer)] = producer
            by_name[producer.name] = producer
        self._identities = identities
        self._by_name = by_name
        self._nonce = _AuthorityNonce(secrets.token_bytes(16))

    @property
    def producer_names(self) -> frozenset[str]:
        """The names of the producers this binder recognizes."""
        return frozenset(self._by_name)

    def owns_nonce(self, nonce: object) -> bool:
        """Whether *nonce* is this instance's private nonce."""
        return nonce is self._nonce

    def recognizes(self, producer: object) -> bool:
        """Whether *producer* is one of this binder's own identity objects."""
        return (
            isinstance(producer, ProducerIdentity)
            and self._identities.get(id(producer)) is producer
        )

    def producer(self, name: object) -> ProducerIdentity:
        """Return this binder's identity object for *name*.

        The lookup is made by *calling code*, which is what vouches; a row's
        claimed name never reaches here.  Unknown names raise rather than
        returning an unregistered stand-in, so a caller cannot accidentally
        bind a producer the binder does not own.
        """
        key = name.value if isinstance(name, Enum) else name
        identity = self._by_name.get(str(key))
        if identity is None:
            raise LookupError(
                f"no producer identity named {key!r} is registered with this "
                "authority"
            )
        return identity

    def mint(self, producer: ProducerIdentity) -> ProducerRegistrationToken:
        """Mint a token for one of this binder's own producer identities."""
        if not self.recognizes(producer):
            raise LookupError(
                "refusing to mint a registration for a producer this authority "
                f"does not own: {getattr(producer, 'name', producer)!r}"
            )
        return ProducerRegistrationToken(
            producer_name=producer.name,
            registration=producer.registration,
            domain=self.RECORD_DOMAIN,
            nonce=self._nonce,
        )

    def bind(self, record: RecordT, producer: ProducerIdentity) -> RecordT:
        """Return *record* registered to *producer*.

        The producer field is rewritten from the identity, so a bound record
        can never name one producer while carrying another's token.
        """
        token = self.mint(producer)
        return replace(
            record,
            **{
                self.RECORD_PRODUCER_FIELD: producer.value,
                self.RECORD_REGISTRATION_FIELD: token,
            },
        )


def producer_registration_of(
    token: object,
    producer_name: str,
    *,
    domain: str,
) -> ProducerRegistration:
    """Read a record's registration from its token, or ``UNKNOWN``.

    A token only counts for the producer *and* the record family it was minted
    for: rewriting a bound record's producer field leaves the token behind, and
    a token minted for another record family does not carry over, so neither
    yields another producer's registration.
    """
    if not isinstance(token, ProducerRegistrationToken):
        return ProducerRegistration.UNKNOWN
    if token.producer_name != producer_name or token.domain != domain:
        return ProducerRegistration.UNKNOWN
    return token.registration


def checked_registration_token(value: object) -> ProducerRegistrationToken | None:
    """Validate a record's registration field at construction time.

    Mirrors the ``trusted`` well-formedness gate: a record either carries a
    genuine minted token or none at all.  Anything else -- notably a boolean,
    which is the shape this replaced -- is a provenance bug, not a value to
    coerce.
    """
    if value is None or isinstance(value, ProducerRegistrationToken):
        return value
    raise TypeError(
        "registration must be a ProducerRegistrationToken minted by a "
        f"ProducerRegistrationAuthority, got {type(value).__name__!r}; "
        "registration is minted by an authority, never set by a producer"
    )


def identities_for_names(
    names: Iterable[object],
    *,
    registration: ProducerRegistration = ProducerRegistration.REGISTERED,
    record_values: Mapping[str, object] | None = None,
) -> tuple[ProducerIdentity, ...]:
    """Build fresh identity objects for *names*.

    Fresh objects on every call: identities are owned by the authority the
    caller is about to build, never shared through module state.
    """
    values = record_values or {}
    identities: list[ProducerIdentity] = []
    for name in names:
        key = name.value if isinstance(name, Enum) else str(name)
        identities.append(
            ProducerIdentity(
                name=str(key),
                registration=registration,
                record_value=values.get(
                    str(key), name if isinstance(name, Enum) else None
                ),
            )
        )
    return tuple(identities)


__all__ = [
    "UNSPECIFIED_PRODUCER",
    "ProducerIdentity",
    "ProducerRegistration",
    "ProducerRegistrationAuthority",
    "ProducerRegistrationToken",
    "checked_registration_token",
    "identities_for_names",
    "producer_registration_of",
]
