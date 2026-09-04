"""Phase-local canonical validation sessions and their work counters.

A session is a *transaction-owned* marker that one unflatten-authority phase is
currently running.  In this first step it only measures: every counter here is
non-authoritative diagnostic metadata.  Nothing in this module may enter a
canonical payload, a content ID, an equality comparison, a verdict, or a
persisted receipt, and no counter value may make validation cheaper yet.

The counters answer one question that the profiles could not: how many times
does one exact object occurrence get deeply validated, wire-encoded, decoded,
and digested inside a single phase?

Counter semantics (all counted at the *top level* of an operation, never once
per recursive node):

``deep_validations``
    Completed :func:`d810.transforms.unflatten_authority.ids.canonical_bytes`
    entries.  Each one recursively revalidates the whole reachable graph.
``wire_encodes``
    Complete wire-tree constructions: ``canonical_bytes`` plus the record
    content-ID preimage builder, which encodes a record without going through
    ``canonical_bytes``.
``roundtrip_decodes``
    Completed ``canonical_decode`` calls.  Each one rebuilds the object graph
    and canonically re-encodes the reconstruction.
``inventory_validations``
    Complete semantic-graph-inventory digest computations, i.e. every full
    inventory validation or mint.
``canonical_bytes_reuses`` / ``content_id_reuses``
    Reuse of an already validated exact occurrence.  Both are structurally
    zero until phase-local reuse exists; they are declared now so the baseline
    and the improved run share one schema.

Attribution counters (added for the canonical hot-path work).  Every session
cache lookup is attributed to exactly one path, so the four ``*_lookup_*``
counters partition the lookups and ``occurrence_stamps`` says how many
top-level recursive :func:`d810.transforms.unflatten_authority.ids._occurrence_stamp`
walks those lookups (plus the inventory seals) cost.  In strict mode each
lookup and each seal mint/check performs exactly one walk, so the walk total
equals the sum of the attributed paths:

``bytes_lookup_hits`` / ``bytes_lookup_misses``
    ``canonical_bytes`` lookups made directly (not on behalf of a content ID).
``content_id_lookup_hits`` / ``content_id_lookup_misses``
    Lookups made by ``content_id``/``authority_id`` (through ``canonical_bytes``)
    and by the record content-ID preimage builder.
``inventory_seal_mints`` / ``inventory_seal_checks`` / ``inventory_seal_hits``
    Semantic-graph-inventory seals recorded after a full validation, seal
    checks performed before an authority consumption, and the checks that
    were satisfied by a seal.
``occurrence_stamps``
    Top-level recursive structural walks performed by ``_occurrence_stamp``.

Set ``D810_AUTHORITY_WORK_COUNTERS`` to a value other than ``""``/``"0"`` to
have the process totals written to standard error at interpreter exit.  That
switch only adds a report; the counters themselves are always maintained.
"""

from __future__ import annotations

import atexit
import builtins
import contextlib
from collections.abc import Iterator, Mapping
from contextvars import ContextVar
from dataclasses import dataclass
from enum import Enum
import json
import os
import sys

_COUNTER_NAMES: tuple[str, ...] = (
    "deep_validations",
    "wire_encodes",
    "roundtrip_decodes",
    "inventory_validations",
    "canonical_bytes_reuses",
    "content_id_reuses",
    "bytes_lookup_hits",
    "bytes_lookup_misses",
    "content_id_lookup_hits",
    "content_id_lookup_misses",
    "inventory_seal_mints",
    "inventory_seal_checks",
    "inventory_seal_hits",
    "occurrence_stamps",
)

_REPORT_ENV = "D810_AUTHORITY_WORK_COUNTERS"
_REPORT_PREFIX = "d810-authority-work-counters"


class CanonicalSessionPhase(Enum):
    """The two exact phases that may own a canonical validation session."""

    PROJECTED_PREPARATION = "projected-preparation"
    OBSERVED_REVALIDATION = "observed-revalidation"


@dataclass(frozen=True, slots=True)
class CanonicalWorkMetrics:
    """Immutable integer work counts for one session or one process."""

    deep_validations: int = 0
    wire_encodes: int = 0
    roundtrip_decodes: int = 0
    inventory_validations: int = 0
    canonical_bytes_reuses: int = 0
    content_id_reuses: int = 0
    bytes_lookup_hits: int = 0
    bytes_lookup_misses: int = 0
    content_id_lookup_hits: int = 0
    content_id_lookup_misses: int = 0
    inventory_seal_mints: int = 0
    inventory_seal_checks: int = 0
    inventory_seal_hits: int = 0
    occurrence_stamps: int = 0

    def __post_init__(self) -> None:
        for name in _COUNTER_NAMES:
            value = getattr(self, name)
            if type(value) is not int:
                raise TypeError(f"{name} must be an exact int")
            if value < 0:
                raise TypeError(f"{name} must be non-negative")

    @property
    def tuple(self) -> tuple[int, ...]:
        """Return the counts in declaration order."""

        return builtins.tuple(getattr(self, name) for name in _COUNTER_NAMES)

    @property
    def total(self) -> int:
        """Return the sum of every counter."""

        return sum(self.tuple)

    def as_payload(self) -> dict[str, int]:
        """Return a key-sorted diagnostic payload.

        >>> CanonicalWorkMetrics(wire_encodes=2).as_payload()["wire_encodes"]
        2
        """

        return {name: getattr(self, name) for name in sorted(_COUNTER_NAMES)}

    def delta(self, earlier: "CanonicalWorkMetrics") -> "CanonicalWorkMetrics":
        """Return ``self - earlier`` for a monotonically earlier snapshot."""

        if type(earlier) is not CanonicalWorkMetrics:
            raise TypeError("delta requires CanonicalWorkMetrics")
        counts = {}
        for name in _COUNTER_NAMES:
            difference = getattr(self, name) - getattr(earlier, name)
            if difference < 0:
                raise ValueError(f"{name} decreased between snapshots")
            counts[name] = difference
        return CanonicalWorkMetrics(**counts)


class _WorkLedger:
    """Mutable counter cells behind one immutable metrics snapshot."""

    __slots__ = _COUNTER_NAMES

    def __init__(self) -> None:
        self.reset()

    def snapshot(self) -> CanonicalWorkMetrics:
        return CanonicalWorkMetrics(
            **{name: getattr(self, name) for name in _COUNTER_NAMES}
        )

    def reset(self) -> None:
        for name in _COUNTER_NAMES:
            setattr(self, name, 0)


#: Types excluded from identity-keyed reuse.  CPython may intern or recycle
#: ``id()`` for these (small ints, short strings, ``True``/``False``/``None``),
#: so identity alone cannot distinguish "the same occurrence" from "an equal
#: but distinct value".  They are also cheap enough that caching buys nothing.
_UNCACHEABLE_OCCURRENCE_TYPES = (type(None), bool, int, str, bytes, float)


def _is_cacheable_occurrence(value: object) -> bool:
    """Report whether ``value`` may be reused by exact-occurrence identity."""

    if type(value) in _UNCACHEABLE_OCCURRENCE_TYPES:
        return False
    if isinstance(value, Enum):
        return False
    return True


class CanonicalValidationSession:
    """One phase-local validation session.

    Beyond counting work, the session holds a strong-reference-guarded cache
    of canonical bytes and record content IDs for exact object occurrences
    that already validated successfully in this session.  A cache hit is
    served only when the stored reference ``is`` the queried object; an
    equal-but-distinct occurrence, a foreign session, or a fresh session
    (including one created after this one closed) always misses.  Nothing
    is ever cached before its underlying validation has fully succeeded, so
    a raising validation can never populate a reusable entry.  The cache is
    released when the session is garbage collected; it must not outlive the
    top-level phase call that created it.
    """

    __slots__ = (
        "_phase", "_ledger", "_closed", "_bytes_cache", "_content_id_cache",
        "_inventory_seals",
    )

    def __init__(self, phase: CanonicalSessionPhase) -> None:
        if type(phase) is not CanonicalSessionPhase:
            raise TypeError("phase must be a CanonicalSessionPhase")
        self._phase = phase
        self._ledger = _WorkLedger()
        self._closed = False
        self._bytes_cache: dict[int, tuple[object, object, bytes]] = {}
        self._content_id_cache: dict[
            tuple[int, str, str], tuple[object, object, str]
        ] = {}
        self._inventory_seals: dict[int, tuple[object, object]] = {}

    @property
    def phase(self) -> CanonicalSessionPhase:
        return self._phase

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def metrics(self) -> CanonicalWorkMetrics:
        """Return the counts recorded so far; readable after close."""

        return self._ledger.snapshot()

    def _require_open(self) -> None:
        if self._closed:
            raise RuntimeError("canonical validation session is closed")

    def record_deep_validation(self) -> None:
        self._require_open()
        self._ledger.deep_validations += 1

    def record_wire_encode(self) -> None:
        self._require_open()
        self._ledger.wire_encodes += 1

    def record_roundtrip_decode(self) -> None:
        self._require_open()
        self._ledger.roundtrip_decodes += 1

    def record_inventory_validation(self) -> None:
        self._require_open()
        self._ledger.inventory_validations += 1

    def record_canonical_bytes_reuse(self) -> None:
        self._require_open()
        self._ledger.canonical_bytes_reuses += 1

    def record_content_id_reuse(self) -> None:
        self._require_open()
        self._ledger.content_id_reuses += 1

    def record_bytes_lookup(self, hit: bool) -> None:
        self._require_open()
        if hit:
            self._ledger.bytes_lookup_hits += 1
        else:
            self._ledger.bytes_lookup_misses += 1

    def record_content_id_lookup(self, hit: bool) -> None:
        self._require_open()
        if hit:
            self._ledger.content_id_lookup_hits += 1
        else:
            self._ledger.content_id_lookup_misses += 1

    def record_inventory_seal_mint(self) -> None:
        self._require_open()
        self._ledger.inventory_seal_mints += 1

    def record_inventory_seal_check(self, hit: bool) -> None:
        self._require_open()
        self._ledger.inventory_seal_checks += 1
        if hit:
            self._ledger.inventory_seal_hits += 1

    def record_occurrence_stamp(self) -> None:
        self._require_open()
        self._ledger.occurrence_stamps += 1

    def cached_canonical_bytes(self, value: object, stamp: object) -> bytes | None:
        """Return canonical bytes already validated for this exact occurrence.

        Returns ``None`` on any miss: an uncacheable primitive, no prior
        entry, or an ``id()`` collision against a different live object.
        """

        self._require_open()
        if not _is_cacheable_occurrence(value):
            return None
        entry = self._bytes_cache.get(id(value))
        if entry is None or entry[0] is not value or entry[1] != stamp:
            return None
        return entry[2]

    def store_canonical_bytes(self, value: object, stamp: object, data: bytes) -> None:
        """Record canonical bytes for an occurrence that just validated."""

        self._require_open()
        if type(data) is not bytes:
            raise TypeError("canonical bytes must be exact bytes")
        if not _is_cacheable_occurrence(value):
            return
        self._bytes_cache[id(value)] = (value, stamp, data)

    def cached_content_id(
        self, value: object, schema: str, omitted_field: str, stamp: object,
    ) -> str | None:
        """Return a record content ID already validated for this occurrence."""

        self._require_open()
        if not _is_cacheable_occurrence(value):
            return None
        entry = self._content_id_cache.get((id(value), schema, omitted_field))
        if entry is None or entry[0] is not value or entry[1] != stamp:
            return None
        return entry[2]

    def store_content_id(
        self, value: object, schema: str, omitted_field: str, stamp: object,
        content_id: str,
    ) -> None:
        """Record a content ID for an occurrence that just validated."""

        self._require_open()
        if type(content_id) is not str:
            raise TypeError("content ID must be an exact str")
        if not _is_cacheable_occurrence(value):
            return
        self._content_id_cache[(id(value), schema, omitted_field)] = (
            value, stamp, content_id,
        )

    def inventory_is_sealed(self, value: object, stamp: object) -> bool:
        """Return whether this exact, unmutated inventory sealed in this session."""

        self._require_open()
        entry = self._inventory_seals.get(id(value))
        return entry is not None and entry[0] is value and entry[1] == stamp

    def seal_inventory(self, value: object, stamp: object) -> None:
        """Record one fully validated inventory occurrence after success only."""

        self._require_open()
        self._inventory_seals[id(value)] = (value, stamp)

    def _close(self) -> None:
        self._closed = True


_ACTIVE_SESSION: ContextVar[CanonicalValidationSession | None] = ContextVar(
    "d810_canonical_validation_session", default=None,
)
_PROCESS_LEDGER = _WorkLedger()


def active_canonical_session() -> CanonicalValidationSession | None:
    """Return the session owning the current context, if any."""

    return _ACTIVE_SESSION.get()


@contextlib.contextmanager
def _canonical_validation_session(
    phase: CanonicalSessionPhase,
    *,
    reuse: CanonicalValidationSession | None = None,
) -> Iterator[CanonicalValidationSession]:
    """Own one phase-local canonical validation session.

    Nested activation is rejected unless ``reuse`` is the exact session that is
    already active for the same phase, which yields it unchanged instead of
    creating a second one.  The context variable token is always reset, so a
    raising phase body cannot leak a session into the next phase.
    """

    if type(phase) is not CanonicalSessionPhase:
        raise TypeError("phase must be a CanonicalSessionPhase")
    active = _ACTIVE_SESSION.get()
    if reuse is not None:
        if reuse is not active:
            raise RuntimeError("reuse requires the exact active session")
        if reuse.phase is not phase:
            raise RuntimeError("reuse requires the same session phase")
        yield reuse
        return
    if active is not None:
        raise RuntimeError("a canonical validation session is already active")
    session = CanonicalValidationSession(phase)
    token = _ACTIVE_SESSION.set(session)
    try:
        yield session
    finally:
        _ACTIVE_SESSION.reset(token)
        session._close()


def record_deep_validation() -> None:
    """Count one completed recursive canonical validation."""

    _PROCESS_LEDGER.deep_validations += 1
    session = _ACTIVE_SESSION.get()
    if session is not None:
        session.record_deep_validation()


def record_wire_encode() -> None:
    """Count one completed top-level wire-tree construction."""

    _PROCESS_LEDGER.wire_encodes += 1
    session = _ACTIVE_SESSION.get()
    if session is not None:
        session.record_wire_encode()


def record_roundtrip_decode() -> None:
    """Count one completed canonical decode (which also re-encodes)."""

    _PROCESS_LEDGER.roundtrip_decodes += 1
    session = _ACTIVE_SESSION.get()
    if session is not None:
        session.record_roundtrip_decode()


def record_inventory_validation() -> None:
    """Count one complete semantic-graph-inventory digest computation."""

    _PROCESS_LEDGER.inventory_validations += 1
    session = _ACTIVE_SESSION.get()
    if session is not None:
        session.record_inventory_validation()


def record_canonical_bytes_reuse() -> None:
    """Count one reuse of an exact occurrence's canonical bytes."""

    _PROCESS_LEDGER.canonical_bytes_reuses += 1
    session = _ACTIVE_SESSION.get()
    if session is not None:
        session.record_canonical_bytes_reuse()


def record_content_id_reuse() -> None:
    """Count one reuse of an exact occurrence's content ID."""

    _PROCESS_LEDGER.content_id_reuses += 1
    session = _ACTIVE_SESSION.get()
    if session is not None:
        session.record_content_id_reuse()


def record_bytes_lookup(hit: bool) -> None:
    """Attribute one direct ``canonical_bytes`` session lookup to hit or miss."""

    if hit:
        _PROCESS_LEDGER.bytes_lookup_hits += 1
    else:
        _PROCESS_LEDGER.bytes_lookup_misses += 1
    session = _ACTIVE_SESSION.get()
    if session is not None:
        session.record_bytes_lookup(hit)


def record_content_id_lookup(hit: bool) -> None:
    """Attribute one content-ID-driven session lookup to hit or miss."""

    if hit:
        _PROCESS_LEDGER.content_id_lookup_hits += 1
    else:
        _PROCESS_LEDGER.content_id_lookup_misses += 1
    session = _ACTIVE_SESSION.get()
    if session is not None:
        session.record_content_id_lookup(hit)


def record_inventory_seal_mint() -> None:
    """Count one inventory seal recorded after a complete validation."""

    _PROCESS_LEDGER.inventory_seal_mints += 1
    session = _ACTIVE_SESSION.get()
    if session is not None:
        session.record_inventory_seal_mint()


def record_inventory_seal_check(hit: bool) -> None:
    """Count one inventory seal check and whether the seal satisfied it."""

    _PROCESS_LEDGER.inventory_seal_checks += 1
    if hit:
        _PROCESS_LEDGER.inventory_seal_hits += 1
    session = _ACTIVE_SESSION.get()
    if session is not None:
        session.record_inventory_seal_check(hit)


def record_occurrence_stamp() -> None:
    """Count one top-level recursive occurrence-stamp walk."""

    _PROCESS_LEDGER.occurrence_stamps += 1
    session = _ACTIVE_SESSION.get()
    if session is not None:
        session.record_occurrence_stamp()


def process_work_metrics() -> CanonicalWorkMetrics:
    """Return the cumulative counts for this interpreter."""

    return _PROCESS_LEDGER.snapshot()


def reset_process_work_metrics() -> None:
    """Zero the cumulative process counts (test and harness use only)."""

    _PROCESS_LEDGER.reset()


def format_work_report(metrics: CanonicalWorkMetrics, *, pid: int) -> str:
    """Return one stable, greppable JSON line for a metrics snapshot."""

    if type(metrics) is not CanonicalWorkMetrics:
        raise TypeError("report requires CanonicalWorkMetrics")
    if type(pid) is not int:
        raise TypeError("pid must be an exact int")
    payload: Mapping[str, int] = {"pid": pid, **metrics.as_payload()}
    return _REPORT_PREFIX + " " + json.dumps(
        payload, sort_keys=True, separators=(",", ":"),
    )


def emit_process_work_report(stream: object = None) -> None:
    """Write the cumulative process report as one line."""

    target = sys.stderr if stream is None else stream
    target.write(
        format_work_report(process_work_metrics(), pid=os.getpid()) + "\n"
    )
    flush = getattr(target, "flush", None)
    if flush is not None:
        flush()


def _report_enabled() -> bool:
    return os.environ.get(_REPORT_ENV, "") not in ("", "0")


if _report_enabled():
    atexit.register(emit_process_work_report)


__all__ = [
    "CanonicalSessionPhase",
    "CanonicalValidationSession",
    "CanonicalWorkMetrics",
    "active_canonical_session",
    "emit_process_work_report",
    "format_work_report",
    "process_work_metrics",
    "record_bytes_lookup",
    "record_canonical_bytes_reuse",
    "record_content_id_lookup",
    "record_content_id_reuse",
    "record_deep_validation",
    "record_inventory_seal_check",
    "record_inventory_seal_mint",
    "record_inventory_validation",
    "record_occurrence_stamp",
    "record_roundtrip_decode",
    "record_wire_encode",
    "reset_process_work_metrics",
]
