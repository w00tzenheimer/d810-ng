"""Detached facts owned by one transaction, without structural interning.

The table stores the actual frozen semantic records. Issuance, rather than a
digest of a duplicate evidence tree, establishes internal occurrence identity.
Only the transaction's private constructors use this table. Public codecs run
with ownership suspended and retain their normal strict validation.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import fields, is_dataclass
from enum import Enum
import json
import math
import os
import sys
from types import MappingProxyType

from d810.core.runtime_identity import RUNTIME_AUTHORITY_SIDECAR_FIELDS


_ACTIVE: ContextVar[TransactionFacts | None] = ContextVar("transaction-facts", default=None)


def active_facts() -> TransactionFacts | None:
    owner = _ACTIVE.get()
    if owner is not None:
        owner.require_open()
    return owner


@contextmanager
def fact_scope(owner):
    if owner is not None:
        owner.require_open()
    token = _ACTIVE.set(owner)
    try:
        yield owner
    finally:
        _ACTIVE.reset(token)


def _exact_fact_graph_equal(left, right, seen=None):
    """Compare canonical fact graphs without invoking value-level equality.

    Exact types are part of the representation: ``True`` is not ``1`` and a
    tuple is not a list.  Registered records are compared through the same
    declared fields as the canonical codec.  This is an exact comparison, not
    an authority digest, so admission does not inherit collision semantics.
    """
    if left is right:
        return True
    if type(left) is not type(right):
        return False
    cls = type(left)
    if left is None or cls in (bool, int, str, bytes):
        return left == right
    if cls is float:
        return left.hex() == right.hex()
    if isinstance(left, Enum):
        return False

    pair = (id(left), id(right))
    seen = set() if seen is None else seen
    if pair in seen:
        return True
    seen.add(pair)
    try:
        if cls in (dict, MappingProxyType):
            from . import ids

            left_map = ids._exact_canonical_mapping(left)
            right_map = ids._exact_canonical_mapping(right)
            if len(left_map) != len(right_map):
                return False
            for key, left_value in dict.items(left_map):
                if type(key) is not str or key not in right_map:
                    return False
                if not _exact_fact_graph_equal(
                    left_value, right_map[key], seen,
                ):
                    return False
            return True
        if cls in (list, tuple):
            return len(left) == len(right) and all(
                _exact_fact_graph_equal(a, b, seen)
                for a, b in zip(left, right)
            )
        if cls is frozenset:
            if len(left) != len(right):
                return False
            unmatched = list(right)
            unmatched_hashes = [hash(item) for item in unmatched]
            for item in left:
                item_hash = hash(item)
                match = next((
                    index
                    for index, candidate in enumerate(unmatched)
                    if unmatched_hashes[index] == item_hash
                    and type(candidate) is type(item)
                    and _exact_fact_graph_equal(item, candidate, seen)
                ), None)
                if match is None:
                    return False
                unmatched.pop(match)
                unmatched_hashes.pop(match)
            return True

        from . import ids

        ids._ensure_registries()
        names = ids._RECORD_FIELDS.get(cls, ids._EXTERNAL_FIELDS.get(cls))
        if names is None:
            return False
        lazy = ids._LAZY_IDENTITY.get(cls, ())

        def field_value(record, name):
            if cls.__name__ == "NativePreanalysisKey" and name == "schema_version":
                return cls.SCHEMA_VERSION
            return getattr(record, name)

        return all(
            _exact_fact_graph_equal(
                field_value(left, name), field_value(right, name), seen,
            )
            for name in names
            if name not in lazy or not ids.lazy_identity_is_pending(left, name)
        )
    finally:
        seen.remove(pair)


class TransactionFacts:
    """One immutable fact graph and a separate observed allocation partition.

    Metrics are operation counts, never validity. ``capture_visits`` includes
    atoms and repeated references; ``captures`` counts uncached compound inputs;
    ``allocations`` counts detached container/record construction plus private
    factory results, and ``table_entries`` includes retained existing values.
    ``validations`` counts constructor invocations added by capture/fact factories.
    Wire reads/builds count the new per-node encoding cache. Resolve counts
    include exact fact/registry/link lookups, including parent lookups. No
    structural nodes are interned by this implementation.
    """

    def __init__(self, *, parent=None):
        if parent is not None:
            parent.require_open()
        self.parent = parent
        self.closed = False
        self._values = {}
        self._copies = {}
        self._capturing = set()
        self._registry = {}
        self._canonical = {}
        self._digests = {}
        self._wire = {}
        self._external = {}
        self._links = {}
        self.metrics = dict(capture_visits=0, captures=0, allocations=0,
                            resolves=0, validations=0, registry_issues=0,
                            encoding_hits=0, encoding_misses=0,
                            parent_encoding_hits=0,
                            immutable_checks=0, wire_reads=0, wire_builds=0,
                            table_entries=0, external_admissions=0,
                            copy_hits=0, links=0)

    def require_open(self):
        if self.closed:
            raise ValueError("transaction fact owner is closed")
        if self.parent is not None:
            self.parent.require_open()

    def close(self):
        if self.closed:
            return
        if os.environ.get("D810_AUTHORITY_WORK_COUNTERS", "0") not in ("", "0"):
            print("d810-authority-transaction-facts " + json.dumps({
                "partition": "projected" if self.parent is None else "observed",
                "owner": id(self), "parent": None if self.parent is None else id(self.parent),
                "metrics": self.metrics,
            }, sort_keys=True), file=sys.stderr)
        self.closed = True
        for table in (self._values, self._copies, self._registry,
                      self._canonical, self._digests, self._wire, self._external, self._links):
            table.clear()

    def contains(self, value):
        self.require_open()
        self.metrics["resolves"] += 1
        return self._values.get(id(value)) is value or (
            self.parent is not None and self.parent.contains(value)
        )

    def _remember(self, source, value):
        self._values[id(value)] = value
        self._copies[id(source)] = (source, value)
        self.metrics["table_entries"] += 1
        return value

    def cached_canonical_bytes(self, value):
        """Find bytes for this exact owned occurrence, including its parent."""
        self.require_open()
        cached = self._canonical.get(id(value))
        if cached is not None and cached[0] is value:
            return cached[1], False
        if self.parent is not None:
            inherited = self.parent.cached_canonical_bytes(value)
            if inherited is not None:
                return inherited[0], True
        return None

    def cached_wire(self, value):
        """Find the mutable wire tree only in this partition."""
        self.require_open()
        cached = self._wire.get(id(value))
        if cached is not None and cached[0] is value:
            return cached[1], False
        return None

    def _finish_staged_admission(self, staging):
        """Adopt one validated staging partition without publishing it first."""
        if type(staging) is not TransactionFacts or staging.parent is not self:
            raise TypeError("external admission staging owner differs")
        staging.require_open()
        if staging._capturing:
            raise ValueError("external admission staging capture is incomplete")
        for name in (
            "_values", "_copies", "_registry", "_canonical", "_digests",
            "_wire", "_external", "_links",
        ):
            target = getattr(self, name)
            source = getattr(staging, name)
            target.update(source)
            source.clear()
        for name, count in staging.metrics.items():
            self.metrics[name] += count
        staging.closed = True

    @staticmethod
    def _discard_staged_admission(staging):
        """Destroy unpublished staging state without emitting work receipts."""
        if type(staging) is not TransactionFacts:
            raise TypeError("external admission staging owner differs")
        staging.closed = True
        for table in (
            staging._values, staging._copies, staging._registry,
            staging._canonical, staging._digests, staging._wire,
            staging._external, staging._links,
        ):
            table.clear()
        staging._capturing.clear()

    def capture(self, value):
        """Detach a new input graph once; existing owned children are references."""
        from . import ids

        self.require_open()
        self.metrics["capture_visits"] += 1
        cls = type(value)
        if value is None or cls in (bool, int, str, bytes):
            return value
        if cls is float:
            if not math.isfinite(value):
                raise ValueError("nonfinite transaction fact")
            return value
        ids._ensure_registries()
        if isinstance(value, Enum):
            if cls not in ids._ENUM_TYPES or cls(value.value) is not value:
                raise ValueError("malformed transaction enum")
            return value
        if self.contains(value):
            return value
        previous = self._copies.get(id(value))
        if previous is not None and previous[0] is value:
            self.metrics["copy_hits"] += 1
            return previous[1]
        if id(value) in self._capturing:
            raise ValueError("cyclic transaction fact")
        self._capturing.add(id(value))
        self.metrics["captures"] += 1
        try:
            if cls is tuple:
                clone = tuple(self.capture(item) for item in value)
            elif cls is frozenset:
                clone = frozenset(self.capture(item) for item in value)
            elif cls is MappingProxyType:
                backing = ids._exact_mappingproxy_backing(value)
                if any(type(key) is not str for key in backing):
                    raise TypeError("fact attributes require exact string keys")
                clone = MappingProxyType({key: self.capture(item) for key, item in backing.items()})
            elif cls in ids._RECORD_FIELDS or cls in ids._EXTERNAL_FIELDS:
                if not is_dataclass(cls) or not cls.__dataclass_params__.frozen:
                    raise TypeError("transaction facts require registered frozen records")
                clone = object.__new__(cls)
                lazy = ids._LAZY_IDENTITY.get(cls, ())
                for field in fields(cls):
                    if field.name in RUNTIME_AUTHORITY_SIDECAR_FIELDS:
                        ids.stage_unpublished_field(clone, field.name, None)
                    elif field.name in lazy:
                        continue
                    else:
                        ids.stage_unpublished_field(clone, field.name, self.capture(getattr(value, field.name)))
                check = getattr(cls, "__post_init__", None)
                if check is not None:
                    self.metrics["validations"] += 1
                    check(clone)
                ids._validate_canonical_value(clone)
            else:
                raise TypeError(f"unsupported transaction fact: {cls.__name__}")
            self.metrics["allocations"] += 1
            return self._remember(value, clone)
        finally:
            self._capturing.remove(id(value))

    def admit_external(self, value, expected_type):
        """Validate and detach public ingress without constructing wire."""
        if type(value) is not expected_type:
            raise TypeError("external fact schema differs")
        self.metrics["external_admissions"] += 1
        source = value
        staging = TransactionFacts(parent=self)
        try:
            with fact_scope(staging):
                snapshot = staging.capture(value)
            if not _exact_fact_graph_equal(source, snapshot):
                raise ValueError("transaction fact capture changed canonical value")
            self._finish_staged_admission(staging)
        finally:
            if not staging.closed:
                self._discard_staged_admission(staging)
        self._copies[id(source)] = (source, snapshot)
        self._external[id(snapshot)] = source
        return snapshot

    def linked_external(self, snapshot, value):
        self.require_open()
        entry = self._external.get(id(snapshot))
        return entry is value or (
            self.parent is not None and self.parent.linked_external(snapshot, value)
        )

    def matches_external(self, snapshot, value):
        # External aliases no longer supply semantic fields after admission.
        # A replaced proposal is a different input; changing an old alias
        # cannot change this owner's detached facts. Native plan/scope checks
        # remain fresh in the transaction API, separately from this link.
        return self.linked_external(snapshot, value)

    def issue(self, registry, value):
        """Publish an already constructor-checked private binder result."""
        value = self.capture(value)
        return self.publish_private(registry, value)

    def publish_private(self, registry, value):
        """Retain a constructor-checked private carrier, without encoding it."""
        self.require_open()
        self._registry[(id(registry), id(value))] = value
        self.metrics["registry_issues"] += 1
        return value

    def link(self, namespace, left, right):
        self.require_open()
        self.metrics["links"] += 1
        self._links[(id(namespace), id(left))] = (left, right)

    def linked(self, namespace, left, right):
        self.require_open()
        self.metrics["resolves"] += 1
        entry = self._links.get((id(namespace), id(left)))
        return (entry is not None and entry[0] is left and entry[1] is right) or (
            self.parent is not None and self.parent.linked(namespace, left, right)
        )

    def registered(self, registry, value):
        self.require_open()
        self.metrics["resolves"] += 1
        return self._registry.get((id(registry), id(value))) is value or (
            self.parent is not None and self.parent.registered(registry, value)
        )

    def immutable(self, value):
        """Recognize an owned root or a new tuple of existing fact references."""
        self.metrics["immutable_checks"] += 1
        if value is None or type(value) in (bool, int, str, bytes):
            return True
        if self.contains(value):
            return True
        if type(value) in (tuple, frozenset) and all(self.immutable(item) for item in value):
            self._values[id(value)] = value
            return True
        if isinstance(value, Enum):
            from . import ids
            ids._ensure_registries()
            return type(value) in ids._ENUM_TYPES and type(value)(value.value) is value
        return False


def captured(value):
    owner = active_facts()
    return value if owner is None else owner.capture(value)


def same_admitted_input(snapshot, external):
    owner = active_facts()
    return snapshot is external or (
        owner is not None and owner.linked_external(snapshot, external)
    )


def construct(cls, *args, **kwargs):
    """Private semantic factory; constructors keep normalization and checks."""
    owner = active_facts()
    if owner is None:
        return cls(*args, **kwargs)
    from . import ids
    ids._ensure_registries()
    if (cls not in ids._RECORD_FIELDS and cls not in ids._EXTERNAL_FIELDS
            or not is_dataclass(cls) or not cls.__dataclass_params__.frozen):
        raise TypeError("private fact factory requires a registered frozen record")
    value = cls(*(owner.capture(item) for item in args),
                **{key: item if key in RUNTIME_AUTHORITY_SIDECAR_FIELDS else owner.capture(item)
                   for key, item in kwargs.items()})
    # The constructor just normalized and checked fields detached above. Its
    # own result is private, so no second reconstruction is necessary.
    owner.metrics["validations"] += 1
    owner.metrics["allocations"] += 1
    return owner._remember(value, value)


def validate_internal(value, expected_type):
    owner = active_facts()
    if owner is not None and type(value) is expected_type and owner.contains(value):
        return value
    from .ids import validate_canonical_roundtrip
    return validate_canonical_roundtrip(value, expected_type)
