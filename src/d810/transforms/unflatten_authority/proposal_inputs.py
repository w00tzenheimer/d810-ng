"""Explicit owned proposal input values; capture conveys no validation authority.

This initial family covers source identity catalogs and use-def witnesses.
Materialization uses
its existing constructors; complete proposal roundtrip checks remain mandatory.
"""

from dataclasses import fields
from types import MappingProxyType

from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.core.structural_identity import StructuralIdentityError
from d810.core.structural_identity import StructuralNodeKind as Kind
from d810.core.structural_identity import StructuralRef, StructuralTable
from d810.ir.block_identity import (
    NativeBlockRef, NativeEaInterval, NativeEaIntervalSet, StableBlockIdentity,
)
from d810.ir.structural_identity import NATIVE_KEY_FIELDS
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.transforms.cfg_transaction import LogicalBlockRef
from d810.transforms.unflatten_authority.model import (
    SourceBlockIdentityWitness, SourceIdentityCatalog, UseDefFragmentWitness,
)


_SOURCE_FIELDS = MappingProxyType({
    SourceIdentityCatalog: ("native_key", "generation", "blocks"),
    SourceBlockIdentityWitness: (
        "block_ref", "anchor_ea", "native_instruction_eas",
    ),
    NativePreanalysisKey: NATIVE_KEY_FIELDS,
    NativeBlockRef: ("identity",),
    LogicalBlockRef: ("session_id", "proxy_token", "version"),
    StableBlockIdentity: ("native_key", "exact_instruction_eas", "native_ranges"),
    NativeEaIntervalSet: ("intervals",),
    NativeEaInterval: ("start_ea", "end_ea"),
    StorageIdentity: ("kind", "offset"),
    UseDefFragmentWitness: (
        "fragment_id", "state_identity", "redirect_owner_refs", "redirect_digest",
        "executed", "fragment_atomic", "actionable_non_state_severance_count",
        "violation_ids",
    ),
})
_SOURCE_TYPES = MappingProxyType({
    (kind.__module__, kind.__qualname__): kind for kind in _SOURCE_FIELDS
})

_SOURCE_ENUMS = MappingProxyType({
    (StorageIdentityKind.__module__, StorageIdentityKind.__qualname__): StorageIdentityKind,
})


def capture_use_def_witness(
    table: StructuralTable, value: UseDefFragmentWitness,
) -> StructuralRef:
    """Detach a use-def witness without certifying its proposal or execution."""
    if type(table) is not StructuralTable or type(value) is not UseDefFragmentWitness:
        raise TypeError("use-def capture requires exact table and witness")
    return _capture(table, value, set())


def materialize_use_def_witness(
    table: StructuralTable, ref: StructuralRef,
) -> UseDefFragmentWitness:
    if type(table) is not StructuralTable or type(ref) is not StructuralRef:
        raise TypeError("use-def read requires exact table and handle")
    node = table.resolve(ref, Kind.SUBJECT)
    if node.payload != (UseDefFragmentWitness.__module__, UseDefFragmentWitness.__qualname__):
        raise StructuralIdentityError("handle does not identify a use-def witness")
    return _materialize(table, ref)


def capture_source_catalog(
    table: StructuralTable, value: SourceIdentityCatalog,
) -> StructuralRef:
    """Copy the exact source family into immutable owner-local terms."""
    if type(table) is not StructuralTable or type(value) is not SourceIdentityCatalog:
        raise TypeError("source catalog capture requires exact table and catalog")
    return _capture(table, value, set())


def _capture(table: StructuralTable, value: object, active: set[int]) -> StructuralRef:
    value_type = type(value)
    if value_type in (type(None), bool, int, str):
        return table.intern(Kind.VALUE, None, (value,), ())
    if value_type is StorageIdentityKind:
        name = object.__getattribute__(value, "_name_")
        encoded_value = object.__getattribute__(value, "_value_")
        if (type(name) is not str or type(encoded_value) is not str
                or value_type.__members__.get(name) is not value):
            raise TypeError("invalid closed storage enum")
        return table.intern(Kind.ENUM, None,
                            (value_type.__module__, value_type.__qualname__, name, encoded_value), ())
    if id(value) in active:
        raise ValueError("source catalog descendant cycle")
    active.add(id(value))
    try:
        if value_type in _SOURCE_FIELDS:
            names = _SOURCE_FIELDS[value_type]
            if tuple(field.name for field in fields(value_type)) != names:
                raise TypeError("source catalog descendant schema drift")
            children = tuple(
                _capture(table, object.__getattribute__(value, name), active)
                for name in names
            )
            return table.intern(
                Kind.SUBJECT, None,
                (value_type.__module__, value_type.__qualname__), children,
            )
        if value_type is tuple:
            children = tuple(_capture(table, item, active) for item in value)
            return table.intern(Kind.SEQUENCE, None, ("tuple",), children)
        if value_type is frozenset:
            # StableBlockIdentity's only set descendant is exact native EAs.
            if any(type(item) is not int for item in value):
                raise TypeError("source identity EAs require exact integers")
            children = tuple(_capture(table, item, active) for item in sorted(value))
            return table.intern(Kind.SEQUENCE, None, ("frozenset",), children)
        raise TypeError("unsupported source catalog descendant")
    finally:
        active.remove(id(value))


def materialize_source_catalog(
    table: StructuralTable, ref: StructuralRef,
) -> SourceIdentityCatalog:
    """Rebuild an independent public value through the existing constructors."""
    if type(table) is not StructuralTable or type(ref) is not StructuralRef:
        raise TypeError("source catalog read requires exact table and handle")
    node = table.resolve(ref, Kind.SUBJECT)
    if node.payload != (SourceIdentityCatalog.__module__, SourceIdentityCatalog.__qualname__):
        raise StructuralIdentityError("handle does not identify a source catalog")
    return _materialize(table, ref)


def _materialize(table: StructuralTable, ref: StructuralRef) -> object:
    node = table.resolve(ref, ref.kind)
    if node.width is not None:
        raise StructuralIdentityError("source term width is outside the schema")
    if ref.kind is Kind.VALUE:
        if (len(node.payload) != 1 or node.children
                or type(node.payload[0]) not in (type(None), bool, int, str)):
            raise StructuralIdentityError("invalid source scalar term")
        return node.payload[0]
    if ref.kind is Kind.ENUM:
        if len(node.payload) != 4 or node.children:
            raise StructuralIdentityError("invalid proposal input enum term")
        enum_type = _SOURCE_ENUMS.get(node.payload[:2])
        name, encoded_value = node.payload[2:]
        if enum_type is None or type(name) is not str or type(encoded_value) is not str:
            raise StructuralIdentityError("unsupported proposal input enum")
        member = enum_type.__members__.get(name)
        if member is None:
            raise StructuralIdentityError("unknown proposal input enum member")
        current_name = object.__getattribute__(member, "_name_")
        current = object.__getattribute__(member, "_value_")
        if (type(current_name) is not str or current_name != name
                or type(current) is not str or current != encoded_value):
            raise StructuralIdentityError("proposal input enum name or value drift")
        return member
    if ref.kind is Kind.SEQUENCE:
        values = tuple(_materialize(table, child) for child in node.children)
        if node.payload == ("tuple",):
            return values
        if node.payload == ("frozenset",) and all(type(item) is int for item in values):
            return frozenset(values)
        raise StructuralIdentityError("invalid source sequence term")
    if ref.kind is not Kind.SUBJECT or node.payload not in _SOURCE_TYPES:
        raise StructuralIdentityError("unsupported source record term")
    record_type = _SOURCE_TYPES[node.payload]
    names = _SOURCE_FIELDS[record_type]
    if len(node.children) != len(names):
        raise StructuralIdentityError("invalid source record field count")
    values = {
        name: _materialize(table, child)
        for name, child in zip(names, node.children)
    }
    return record_type(**values)
