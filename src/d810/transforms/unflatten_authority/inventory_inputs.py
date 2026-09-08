"""Explicit inventory capture into the existing phase-owned structural table.

Capture copies values once and grants no reusable validation authority.
"""

from dataclasses import fields
from types import MappingProxyType

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


