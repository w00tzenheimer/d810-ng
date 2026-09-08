"""Explicit inventory capture into the existing phase-owned structural table.

Capture copies values once and grants no reusable validation authority.
"""

from dataclasses import fields
from types import MappingProxyType

from d810.core.structural_identity import StructuralIdentityError
from d810.core.structural_identity import StructuralNodeKind as Kind
from d810.core.structural_identity import StructuralRef, StructuralTable
from d810.transforms.unflatten_authority import model, proposal_inputs
from d810.transforms.unflatten_authority.inventory_values import INVENTORY_FIELDS


_RECORD_TYPES = (
    model.SemanticGraphInventory,
    model.InventoryBlockObservation,
    model.InventoryInstructionObservation,
    model.InventoryPredicateObservation,
    model.PhaseSubjectBinding,
    model.InventoryEffectSite,
    model.InventoryTerminalSite,
    model.InventoryTopologyIncidence,
    model.ObservedLogicalEndpointOccurrence,
    model.ObservedRouteTopologyOccurrence,
    model.ObservedLoweredConditionalTopologyOccurrence,
    model.PatchStepEvidencePayload,
    model.TopologyEdgeRelation,
)
_FIELDS = MappingProxyType({cls: INVENTORY_FIELDS[cls.__name__] for cls in _RECORD_TYPES})
_ENUMS = (
    model.UnflattenAuthorityPhase, model.SubjectBindingStatus,
    model.TopologyIncidenceKind, model.BlockKind, model.InsnKind,
    model.ControlTransferKind, model.CallKind, model.PredicateKind,
)


def capture_inventory(table: StructuralTable, value: model.SemanticGraphInventory) -> StructuralRef:
    """Own one explicit inventory value without granting validation reuse."""
    if type(table) is not StructuralTable or type(value) is not model.SemanticGraphInventory:
        raise TypeError("inventory capture requires exact table and inventory")
    return _capture(table, value, set())


def capture_inventory_reference(table: StructuralTable, value: object) -> StructuralRef:
    """Publish one claim join key in the inventory's own partition."""
    if type(table) is not StructuralTable or type(value) not in (
        model.NativeBlockRef, model.LogicalBlockRef, model.PlanBlockRef,
    ):
        raise TypeError("inventory join requires an exact owner and block reference")
    return proposal_inputs._capture(table, value, set())


def _capture(table: StructuralTable, value: object, active: set[int]) -> StructuralRef:
    cls = type(value)
    if cls in _ENUMS:
        name = object.__getattribute__(value, "_name_")
        raw = object.__getattribute__(value, "_value_")
        if (type(name) is not str or type(raw) not in (str, int)
                or cls.__members__.get(name) is not value or cls(raw) is not value):
            raise TypeError("inventory enum is outside its closed value schema")
        return table.intern(Kind.ENUM, None, (cls.__module__, cls.__qualname__, name, raw), ())
    if cls not in _FIELDS and cls is not tuple:
        return proposal_inputs._capture(table, value, active)
    if id(value) in active:
        raise ValueError("inventory descendant cycle")
    active.add(id(value))
    try:
        if cls is tuple:
            return table.intern(Kind.SEQUENCE, None, ("tuple",),
                                tuple(_capture(table, item, active) for item in value))
        names = _FIELDS[cls]
        if tuple(item.name for item in fields(cls)) != names:
            raise TypeError("inventory record schema drift")
        children = tuple(_capture(table, object.__getattribute__(value, name), active)
                         for name in names)
        return table.intern(Kind.SUBJECT, None, (cls.__module__, cls.__qualname__), children)
    finally:
        active.remove(id(value))




_RECORD_TAGS = MappingProxyType({(cls.__module__, cls.__qualname__): cls for cls in _RECORD_TYPES})
_ENUM_TAGS = MappingProxyType({(cls.__module__, cls.__qualname__): cls for cls in _ENUMS})


def materialize_inventory(table: StructuralTable, root: StructuralRef) -> model.SemanticGraphInventory:
    """Replay constructors once at publication, never from a steady reader."""
    if type(table) is not StructuralTable:
        raise TypeError("inventory materialization requires an exact owner")
    node = table.resolve(root, Kind.SUBJECT)
    if node.payload != (model.SemanticGraphInventory.__module__, model.SemanticGraphInventory.__qualname__):
        raise StructuralIdentityError("owned root is not an inventory")
    return _materialize(table, root)


def _materialize(table: StructuralTable, ref: StructuralRef) -> object:
    node = table.resolve(ref, ref.kind)
    if node.width is not None:
        raise StructuralIdentityError("inventory term has a foreign width")
    if node.kind is Kind.SEQUENCE and node.payload == ("tuple",):
        return tuple(_materialize(table, child) for child in node.children)
    if node.kind is Kind.ENUM and node.payload[:2] in _ENUM_TAGS:
        if len(node.payload) != 4 or node.children:
            raise StructuralIdentityError("inventory enum has a foreign schema")
        cls = _ENUM_TAGS[node.payload[:2]]
        name, raw = node.payload[2:]
        if type(name) is not str or type(raw) not in (str, int):
            raise StructuralIdentityError("inventory enum is not closed")
        member = cls(raw)
        if (type(object.__getattribute__(member, "_name_")) is not str
                or object.__getattribute__(member, "_name_") != name
                or type(object.__getattribute__(member, "_value_")) is not type(raw)
                or object.__getattribute__(member, "_value_") != raw):
            raise StructuralIdentityError("inventory enum name or value drift")
        return member
    if node.kind is Kind.SUBJECT and node.payload in _RECORD_TAGS:
        cls = _RECORD_TAGS[node.payload]
        names = _FIELDS[cls]
        if len(node.children) != len(names):
            raise StructuralIdentityError("inventory record has a foreign field count")
        return cls(**{name: _materialize(table, child) for name, child in zip(names, node.children)})
    return proposal_inputs._materialize(table, ref)
