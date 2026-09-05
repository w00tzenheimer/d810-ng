"""Scope-owned runtime references for process-local authority joins.

An authority identity has historically been a content-derived SHA-256 string.
That representation is required at a persistence or decode boundary, where a
reader must reproduce the identity from the immutable content it names.  It is
pure overhead for an identity that never leaves the process and only serves as
a join or ordering key: constructing it walks and JSON-encodes an entire record
graph, and validating it walks the same graph again.

``RuntimeAuthorityScope`` mints such join keys directly.  A scope owns one
private ``object()`` token; that exact token participates in the equality and
hash of every reference it mints, so two references with the same kind and
ordinal from two different scopes are different values.  There is no global
registry, no UUID, no content hash, and no persistence codec: a reference is
meaningful only while its minting scope is reachable, and the canonical encoder
refuses to serialize one.

This module lives in ``d810.core`` because both producer-side analyses
(``d810.analyses.control_flow``) and the authority transaction
(``d810.transforms.unflatten_authority``) mint references, and the layered
architecture forbids ``d810.analyses`` from importing ``d810.transforms``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

RUNTIME_AUTHORITY_ID_PREFIX = "runtime:"
"""Marker that distinguishes a scope-derived identity from a content-derived one.

Validation at a persistence or decode boundary keys off this prefix: an
identity that does not carry it is still required to be reproducible from its
content, so relaxing the check for runtime references does not weaken the
content-derived guarantee for anything else.
"""


class RuntimeAuthorityKind(IntEnum):
    """Closed set of authority records that may carry one runtime reference."""

    ROUTE_GROUP = 1
    ROUTE_PROOF = 2
    SUBJECT = 3
    CLAIM = 4
    EVIDENCE = 5
    JUSTIFICATION = 6
    CASE = 7
    INVENTORY = 8
    BINDING = 9
    LEDGER = 10
    DELTA = 11


@dataclass(frozen=True, slots=True)
class RuntimeAuthorityRef:
    """One scope-local join reference, complete and immutable at construction.

    ``_owner`` is the private token of the minting scope.  It is a plain
    ``object()`` whose equality is identity, so it makes this reference unequal
    to an identically numbered reference from any other scope.

    >>> scope = RuntimeAuthorityScope("0x1400:g3")
    >>> other = RuntimeAuthorityScope("0x1400:g3")
    >>> scope.mint(RuntimeAuthorityKind.CLAIM) == other.mint(
    ...     RuntimeAuthorityKind.CLAIM
    ... )
    False
    """

    kind: RuntimeAuthorityKind
    ordinal: int
    _owner: object = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.kind) is not RuntimeAuthorityKind:
            raise TypeError("runtime reference requires a runtime authority kind")
        if type(self.ordinal) is not int:
            raise TypeError("runtime reference ordinal must be an exact int")
        if self.ordinal < 1:
            raise ValueError("runtime reference ordinal must be positive")
        if self._owner is None:
            raise TypeError("runtime reference requires a scope owner token")

    def render(self) -> str:
        """Return the readable, scope-relative rendering of this reference.

        The ordinal is zero padded so that lexicographic ordering of rendered
        references agrees with mint order.

        >>> RuntimeAuthorityScope("ns").mint(
        ...     RuntimeAuthorityKind.ROUTE_PROOF
        ... ).render()
        'route_proof000001'
        """

        return f"{self.kind.name.lower()}{self.ordinal:06d}"

    def __str__(self) -> str:
        return self.render()


class RuntimeAuthorityScope:
    """Mint join references owned by exactly one live analysis or transaction.

    >>> scope = RuntimeAuthorityScope("0x1400:g3")
    >>> ref = scope.mint(RuntimeAuthorityKind.ROUTE_GROUP)
    >>> scope.owns(ref)
    True
    >>> scope.identity(ref)
    'runtime:0x1400:g3#route_group000001'
    """

    __slots__ = ("_counters", "_namespace", "_token")

    def __init__(self, namespace: str) -> None:
        normalized = str(namespace).strip()
        if not normalized:
            raise ValueError("runtime authority scope requires a namespace")
        self._namespace = normalized
        self._token = object()
        self._counters: dict[RuntimeAuthorityKind, int] = {}

    @property
    def namespace(self) -> str:
        """Return the readable namespace shared by every identity of this scope."""

        return self._namespace

    def mint(self, kind: RuntimeAuthorityKind) -> RuntimeAuthorityRef:
        """Return the next reference of ``kind``, numbered from one."""

        if type(kind) is not RuntimeAuthorityKind:
            raise TypeError("runtime authority kind is not a RuntimeAuthorityKind")
        ordinal = self._counters.get(kind, 0) + 1
        self._counters[kind] = ordinal
        return RuntimeAuthorityRef(kind, ordinal, self._token)

    def owns(self, ref: RuntimeAuthorityRef) -> bool:
        """Return whether ``ref`` was minted by exactly this scope."""

        if type(ref) is not RuntimeAuthorityRef:
            raise TypeError("owns requires a runtime authority reference")
        return ref._owner is self._token

    def identity(self, ref: RuntimeAuthorityRef) -> str:
        """Return the readable identity string for one reference of this scope."""

        if not self.owns(ref):
            raise ValueError(
                "runtime reference belongs to another runtime authority scope"
            )
        return f"{RUNTIME_AUTHORITY_ID_PREFIX}{self._namespace}#{ref.render()}"

    def __repr__(self) -> str:
        minted = sum(self._counters.values())
        return (
            f"RuntimeAuthorityScope(namespace={self._namespace!r}, minted={minted})"
        )


def is_runtime_authority_identity(value: object) -> bool:
    """Return whether ``value`` is a scope-derived rather than content identity.

    >>> is_runtime_authority_identity("runtime:0x1400:g3#route_proof000001")
    True
    >>> is_runtime_authority_identity("sha256:" + "0" * 64)
    False
    """

    return type(value) is str and value.startswith(RUNTIME_AUTHORITY_ID_PREFIX)


__all__ = [
    "RUNTIME_AUTHORITY_ID_PREFIX",
    "RuntimeAuthorityKind",
    "RuntimeAuthorityRef",
    "RuntimeAuthorityScope",
    "is_runtime_authority_identity",
]
