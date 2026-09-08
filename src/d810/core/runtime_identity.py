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

A reference names a record; ``RuntimeAuthorityArena`` is what holds the
mapping.  The arena belongs to the phase or session that opens it, is created
with its scope and dies with it, and answers only for the references it minted
itself -- so identity and content stay separate concepts: a content ID remains
the fingerprint a reader can reproduce from persisted bytes, while a reference
is the authority for a join that never leaves the process.

This module lives in ``d810.core`` because both producer-side analyses
(``d810.analyses.control_flow``) and the authority transaction
(``d810.transforms.unflatten_authority``) mint references, and the layered
architecture forbids ``d810.analyses`` from importing ``d810.transforms``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

from d810.core.structural_identity import StructuralTable

RUNTIME_AUTHORITY_ID_PREFIX = "runtime:"
"""Marker that distinguishes a scope-derived identity from a content-derived one.

Validation at a persistence or decode boundary keys off this prefix: an
identity that does not carry it is still required to be reproducible from its
content, so relaxing the check for runtime references does not weaken the
content-derived guarantee for anything else.
"""


RUNTIME_CLAIM_SIDECAR_FIELD = "_runtime_refs"
"""Name of the sidecar slot a claim record carries its arena references in.

Named once, here, so the factory that writes the slot and the walkers that
skip it cannot drift apart: it is a member of
``RUNTIME_AUTHORITY_SIDECAR_FIELDS`` by construction below, which
``tests/unit/core/test_runtime_authority_arena.py`` pins.
"""


RUNTIME_SUBJECT_SIDECAR_FIELD = "_runtime_ref"
"""Name of the sidecar slot a semantic subject carries its reference in.

Named once, here, for the same reason as
``RUNTIME_CLAIM_SIDECAR_FIELD``: the factory that writes the slot and the
walkers that skip it must not drift apart.
"""


RUNTIME_VERDICT_SIDECAR_FIELD = "_route_authority_verification"
"""Name of the sidecar slot a verdict records its seam verification in.

Named once, here, for the same reason as the other three: the code that writes
the slot and the walkers that skip it must not drift apart.  Unlike the others
this one holds no live scope -- it is a plain enum member recording *what the
producer/transaction seam was able to verify* -- but it is a sidecar by the
same rule: it is process-local provenance, not content, so it is outside the
canonical schema and is never encoded or persisted.
"""


RUNTIME_AUTHORITY_SIDECAR_FIELDS = frozenset({
    "_runtime_identity",
    "_runtime_binding",
    RUNTIME_CLAIM_SIDECAR_FIELD,
    RUNTIME_SUBJECT_SIDECAR_FIELD,
    RUNTIME_VERDICT_SIDECAR_FIELD,
})
"""Closed set of private dataclass fields that carry live runtime authority.

A record may carry a *sidecar*: a private, ``compare=False`` field holding a
scope or an arena binding.  It is deliberately outside the record's canonical
schema -- absent from ``ids._RECORD_FIELDS``, from the wire encoding and from
the record's equality -- because a live process-local authority is not
content and cannot be serialized, detached or hashed.

Five names are in it: ``_runtime_identity`` (the minting scope of an
internally produced route bundle), ``_runtime_binding`` (the arena that is the
join authority for that bundle), ``_runtime_refs`` (the references a record
minted *from* a bundle -- a claim -- carries so a join need not read its
content ID), ``_runtime_ref`` (the single reference a semantic subject carries,
minted by the transaction session that constructed it) and
``_route_authority_verification`` (what the producer/transaction seam was able
to verify, recorded on the verdict so it outlives the session that decided it).

**Generic walkers enumerate ``dataclasses.fields`` rather than the schema, so
they see these fields anyway, and the codebase skips them by two different
mechanisms.**  Both are sound; which one a walker uses follows from what it
is walking.

1. *This closed set*, at the three sites that must distinguish a sidecar from
   any other private field: ``bind._is_runtime_authority_sidecar`` (used by
   ``_registry_structural_snapshot`` and ``_detached_canonical_copy``) and
   ``model._structural_key``.  They cannot use a "private" rule, because they
   would then also swallow private *construction markers* such as
   ``ObligationEvidenceIndex._token`` and ``PreparationAuthorityReceipt._minted``,
   whose ``__post_init__`` requires them to be present -- a detached copy
   without them raises.  Adding a sidecar therefore means adding its name
   here, on purpose and visibly.

2. *A ``name.startswith("_")`` skip*, at the walkers whose subject is a
   record's **canonical schema** rather than its storage:
   ``ids._ensure_registries`` (schema drift), ``model._validate_inventory_refs``,
   ``model._claim_subjects``, ``SemanticSafetyCase``'s occurrence
   revalidation, ``bind._route_failure_identity`` / ``_route_result_identity``
   and the ``proposal`` patch-step walkers.  This is safe -- and stricter than
   it looks -- because ``ids._ensure_registries`` *defines* the canonical
   schema as ``fields(record_type)`` minus every underscore-prefixed name and
   raises ``canonical record schema drift`` otherwise.  A private field
   therefore cannot be canonical, so "skip private" and "skip non-canonical"
   are the same predicate at those sites, and it needs no maintenance when a
   sidecar is added.

The distinction is not stylistic: mechanism 1 answers "is this field live
runtime authority", mechanism 2 answers "is this field part of the canonical
schema".  A walker that needs the first must not use the second, because a
construction marker is private and is not authority.
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


class RuntimeAuthorityArenaError(RuntimeError):
    """Every fail-closed rejection a runtime authority arena can raise.

    One exception type covers the three rejections that mean the same thing --
    *this arena is not the authority for that reference* -- so a caller that
    must fail closed catches one class instead of guessing between
    ``KeyError`` and ``ValueError``.  A wrong *type* is still a ``TypeError``:
    that is a programming error, not an authority decision.
    """


class RuntimeJoinRejected(ValueError):
    """Fail-closed refusal of a runtime join.

    An arena raises :class:`RuntimeAuthorityArenaError` for *its* three
    rejections.  A join is a different vocabulary: it asks whether the records
    in hand may be correlated at all, and its callers live outside this module.
    Every holder of an arena therefore translates the arena's exception into
    this one at its own boundary, so a join site catches exactly one class and
    the arena's internal exception never escapes into calling code.

    The three refusals that reach a join, all of them deliberate:

    * a value that was never bound to an arena -- a decoded or directly
      constructed record -- reaching a join without an explicit rebind;
    * a reference or a record belonging to a different arena;
    * a reference whose arena has been closed by its lifecycle owner.

    **It derives from ``ValueError`` on purpose.**  Every one of those three is
    a statement that the *input* to a join is not admissible, which is what a
    ``ValueError`` means in this codebase, and the whole deobfuscation
    pipeline's graceful-abstention contract is written as
    ``except (TypeError, ValueError)``: the emitter converts such a failure
    into "produce no plan" rather than into a crash inside a decompilation.
    A ``RuntimeError`` would have travelled straight through every one of
    those handlers, so a proof that is merely not this bundle's record would
    abort the pass instead of declining it.

    >>> issubclass(RuntimeJoinRejected, ValueError)
    True
    """


class RuntimeAuthorityArena:
    """Bind the references one scope mints to the records they name.

    The arena is owned by the lifecycle object that creates it -- a producer
    phase or a transaction session -- and it is created with its scope and dies
    with it.  It is never module level and never process global: two arenas
    over the same namespace share nothing, because the references they hand out
    carry different owner tokens.

    It *wraps* a scope rather than constructing one, so a producer that already
    holds a scope (and has already handed it to a record such as
    ``RuntimeRouteIdentity``) can open an arena over exactly that scope without
    changing the identity of anything already minted.

    A record is built complete before it is minted and the arena never mutates
    it; ``get`` returns the exact object that was stored.  Only a frozen
    dataclass or a ``NamedTuple`` may be minted, so that "the exact object" is
    also an object nobody else can rebind a field of (see
    ``_require_immutable`` for what that does and does not cover).

    >>> from dataclasses import dataclass, replace
    >>> @dataclass(frozen=True)
    ... class Claim:
    ...     label: str
    >>> arena = RuntimeAuthorityArena(RuntimeAuthorityScope("0x1400:g3"))
    >>> ref = arena.mint(RuntimeAuthorityKind.CLAIM, Claim("exact effect"))
    >>> arena.get(ref)
    Claim(label='exact effect')
    >>> arena.owns(ref)
    True
    >>> len(arena)
    1

    A copy is a different record; the arena keeps the one it was given.

    >>> replace(arena.get(ref), label="rewritten") is arena.get(ref)
    False
    >>> arena.get(ref).label
    'exact effect'

    Closing the arena ends its authority, and releases the records it held.

    >>> arena.close()
    >>> arena.get(ref)
    Traceback (most recent call last):
        ...
    d810.core.runtime_identity.RuntimeAuthorityArenaError: runtime authority arena is closed
    """

    __slots__ = ("_by_kind", "_closed", "_records", "_scope", "_structural")

    def __init__(self, scope: RuntimeAuthorityScope) -> None:
        if type(scope) is not RuntimeAuthorityScope:
            raise TypeError(
                "runtime authority arena requires a runtime authority scope"
            )
        self._scope = scope
        self._records: dict[RuntimeAuthorityRef, object] = {}
        self._by_kind: dict[RuntimeAuthorityKind, list[RuntimeAuthorityRef]] = {}
        self._closed = False
        self._structural: StructuralTable | None = None

    @property
    def structural(self) -> StructuralTable:
        """Return this arena-owned structural partition, allocated on demand."""
        self._require_open()
        if self._structural is None:
            self._structural = StructuralTable()
        return self._structural

    @property
    def scope(self) -> RuntimeAuthorityScope:
        """Return the one scope whose references this arena resolves."""

        return self._scope

    @property
    def namespace(self) -> str:
        """Return the readable namespace of this arena's scope."""

        return self._scope.namespace

    @property
    def is_closed(self) -> bool:
        """Return whether this arena has been closed by its owner."""

        return self._closed

    def mint(
        self, kind: RuntimeAuthorityKind, record: object
    ) -> RuntimeAuthorityRef:
        """Store one complete, immutable ``record`` under a fresh reference.

        Every argument is validated before an ordinal is consumed, so a
        rejected mint leaves the scope's numbering untouched.

        >>> from dataclasses import dataclass
        >>> @dataclass(frozen=True)
        ... class Proof:
        ...     label: str
        >>> arena = RuntimeAuthorityArena(RuntimeAuthorityScope("ns"))
        >>> arena.mint(RuntimeAuthorityKind.ROUTE_PROOF, Proof("p")).render()
        'route_proof000001'
        """

        self._require_open()
        if type(kind) is not RuntimeAuthorityKind:
            raise TypeError("runtime authority kind is not a RuntimeAuthorityKind")
        self._require_immutable(record)
        ref = self._scope.mint(kind)
        self._records[ref] = record
        self._by_kind.setdefault(kind, []).append(ref)
        return ref

    def get(self, ref: RuntimeAuthorityRef) -> object:
        """Return the exact record ``ref`` names, or fail closed.

        A reference minted by another scope, or by this arena's scope but not
        through this arena, is rejected: an arena answers only for what it
        minted itself.
        """

        self._require_open()
        if not self._scope.owns(ref):
            raise RuntimeAuthorityArenaError(
                "runtime reference belongs to another runtime authority scope"
            )
        try:
            return self._records[ref]
        except KeyError:
            raise RuntimeAuthorityArenaError(
                "this runtime authority arena never minted that reference"
            ) from None

    def owns(self, ref: RuntimeAuthorityRef) -> bool:
        """Return whether this arena minted ``ref`` and still holds its record.

        This is strictly stronger than ``arena.scope.owns(ref)``, which answers
        only that the scope numbered the reference.
        """

        self._require_open()
        return self._scope.owns(ref) and ref in self._records

    def refs(self, kind: RuntimeAuthorityKind) -> tuple[RuntimeAuthorityRef, ...]:
        """Return this arena's references of ``kind`` in mint order."""

        return self._ordered(kind)

    def records(self, kind: RuntimeAuthorityKind) -> tuple[object, ...]:
        """Return this arena's records of ``kind`` in mint order."""

        return tuple(self._records[ref] for ref in self._ordered(kind))

    def close(self) -> None:
        """End this arena's authority and release the records it held.

        Closing is idempotent, and it is the lifecycle owner's job: the arena
        never closes itself.
        """

        self._closed = True
        if self._structural is not None:
            self._structural.close()
        self._records = {}
        self._by_kind = {}

    def __len__(self) -> int:
        """Return how many records this arena currently holds.

        This is a size question rather than an authority question, so it stays
        answerable after ``close``, where it reports zero: a closed arena holds
        nothing.  Every authority question (``mint``, ``get``, ``owns``,
        ``refs``, ``records``) raises instead.
        """

        return len(self._records)

    def __repr__(self) -> str:
        return (
            f"RuntimeAuthorityArena(namespace={self._scope.namespace!r}, "
            f"records={len(self._records)}, closed={self._closed})"
        )

    def _require_open(self) -> None:
        if self._closed:
            raise RuntimeAuthorityArenaError("runtime authority arena is closed")

    def _ordered(
        self, kind: RuntimeAuthorityKind
    ) -> tuple[RuntimeAuthorityRef, ...]:
        self._require_open()
        if type(kind) is not RuntimeAuthorityKind:
            raise TypeError("runtime authority kind is not a RuntimeAuthorityKind")
        return tuple(self._by_kind.get(kind, ()))

    @staticmethod
    def _require_immutable(record: object) -> None:
        """Accept only a record type whose own attributes cannot be rebound.

        This is an **allowlist**: an authority record is an instance of a
        frozen dataclass or of a ``NamedTuple``, and nothing else is stored.
        Both of those raise on ``record.field = value``, which is exactly and
        only what the arena promises -- the object it hands back is the object
        that was minted, and no holder of that object can rebind a field of it
        behind the arena's back.

        A denylist cannot make that promise.  A plain instance is not ``None``,
        not a mutable dataclass and not a builtin container, yet
        ``record.field = value`` rebinds it silently, so any "reject the
        obviously mutable" rule admits exactly the case the promise is about.

        Immutable-but-unnamed values (``str``, ``int``, ``tuple``,
        ``frozenset``, ...) are rejected too.  They cannot be mutated, but an
        authority record is a named record type; a caller that wants to store a
        tuple wraps it in a frozen dataclass, which also gives the thing a name
        in every diagnostic that prints it.

        What is **not** enforced, and is the documented remaining gap: the arena
        does not walk the record graph, so a frozen record whose field holds a
        list is accepted and that list stays mutable.  Walking a record graph on
        every mint is the cost this whole change exists to remove.  The
        guarantee is one level deep, on the record object itself.
        """

        if not isinstance(record, type):
            params = getattr(type(record), "__dataclass_params__", None)
            if params is not None and params.frozen is True:
                return
            if isinstance(record, tuple) and hasattr(type(record), "_fields"):
                return
        raise TypeError(
            "runtime authority arena requires a frozen dataclass or NamedTuple "
            f"record, not {type(record).__name__}"
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
    "RUNTIME_AUTHORITY_SIDECAR_FIELDS",
    "RUNTIME_CLAIM_SIDECAR_FIELD",
    "RUNTIME_SUBJECT_SIDECAR_FIELD",
    "RUNTIME_VERDICT_SIDECAR_FIELD",
    "RuntimeAuthorityArena",
    "RuntimeAuthorityArenaError",
    "RuntimeAuthorityKind",
    "RuntimeAuthorityRef",
    "RuntimeAuthorityScope",
    "RuntimeJoinRejected",
    "is_runtime_authority_identity",
]
