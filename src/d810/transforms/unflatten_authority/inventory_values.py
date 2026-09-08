"""Owned inventory readers; no mutable model imports or reconstruction.

These readers resolve issued refs and exact scalar columns. They do not grant
validation authority or retain public inventory records.
"""

from types import MappingProxyType

from d810.core.structural_identity import StructuralIdentityError
from d810.core.structural_identity import StructuralNodeKind as Kind
from d810.core.structural_identity import StructuralNode, StructuralRef, StructuralTable


INVENTORY_FIELDS = MappingProxyType({
    "SemanticGraphInventory": (
        "phase", "graph_fingerprint", "generation", "blocks", "subjects",
        "bindings", "effects", "terminals", "topology", "inventory_digest",
        "reachable_serials", "entry_serial", "source_subject_ids", "function_ea",
        "observed_route_topology_occurrences",
        "observed_lowered_conditional_topology_occurrences",
    ),
    "InventoryBlockObservation": (
        "serial", "block_ref", "anchor_ea", "native_instruction_eas",
        "predecessor_serials", "successor_serials", "transfer_ea",
        "instruction_observations", "block_kind", "graph_start_ea",
        "tail_opcode", "raw_tail_opcode", "tail_kind",
    ),
    "InventoryInstructionObservation": (
        "ordinal", "instruction_ea", "opcode", "width", "instruction_kind",
        "control_transfer_kind", "is_call", "call_kind", "display_text",
        "predicate_observation", "raw_opcode",
    ),
    "InventoryPredicateObservation": (
        "predicate_kind", "storage_identity", "width", "compare_constant",
        "explicit_target_serial",
    ),
    "PhaseSubjectBinding": (
        "subject", "phase", "block_ref", "graph_fingerprint", "generation",
        "status", "serial", "anchor_ea", "native_instruction_eas", "role",
        "observed_logical_occurrence",
    ),
    "InventoryEffectSite": (
        "owner_serial", "owner_ref", "owner_anchor_ea", "instruction_ordinal",
        "instruction_ea", "effect_kind", "opcode", "width",
    ),
    "InventoryTerminalSite": (
        "owner_serial", "owner_ref", "owner_anchor_ea", "instruction_ordinal",
        "instruction_ea", "terminal_kind",
    ),
    "InventoryTopologyIncidence": (
        "kind", "owner_serial", "peer_serial", "source_transfer_ea",
    ),
    "ObservedLogicalEndpointOccurrence": (
        "logical_ref", "projected_serial", "observed_serial", "owner_ref",
        "predecessor_refs",
    ),
    "ObservedRouteTopologyOccurrence": (
        "relation_id", "row_id", "patch_fact", "normalized_pairs",
    ),
    "ObservedLoweredConditionalTopologyOccurrence": (
        "patch_fact", "source_ref", "false_target_ref", "true_target_ref",
        "normalized_pairs",
    ),
    "PatchStepEvidencePayload": (
        "plan_id", "step_index", "step_type", "owner_ref", "step_digest",
        "host_ea", "host_opcode", "value_size", "creation_spec_digest",
    ),
    "TopologyEdgeRelation": (
        "role", "source_subject_id", "target_subject_id", "native_edge_anchor_ea",
    ),
})
_MODEL_MODULE = "d810.transforms.unflatten_authority.model"
_FIELD_TAGS = MappingProxyType({
    (_MODEL_MODULE, name): names for name, names in INVENTORY_FIELDS.items()
})
_INVENTORY_TAG = (_MODEL_MODULE, "SemanticGraphInventory")


def _resolve(table: StructuralTable, ref: StructuralRef, kind: Kind) -> StructuralNode:
    if type(table) is not StructuralTable:
        raise TypeError("inventory reader requires the exact structural owner")
    return table.resolve(ref, kind)


def record_field(table: StructuralTable, ref: StructuralRef, name: str) -> StructuralRef:
    """Read a field handle without borrowing a mutable record."""
    node = _resolve(table, ref, Kind.SUBJECT)
    names = _FIELD_TAGS.get(node.payload)
    if node.width is not None or names is None or len(node.children) != len(names):
        raise StructuralIdentityError("invalid owned inventory record schema")
    if type(name) is not str or name not in names:
        raise StructuralIdentityError("unknown owned inventory field")
    return node.children[names.index(name)]


def inventory_field(table: StructuralTable, ref: StructuralRef, name: str) -> StructuralRef:
    node = _resolve(table, ref, Kind.SUBJECT)
    if node.payload != _INVENTORY_TAG:
        raise StructuralIdentityError("owned value is not an inventory")
    return record_field(table, ref, name)


def sequence_children(table: StructuralTable, ref: StructuralRef) -> tuple[StructuralRef, ...]:
    node = _resolve(table, ref, Kind.SEQUENCE)
    if node.width is not None or node.payload != ("tuple",):
        raise StructuralIdentityError("invalid owned inventory tuple")
    return node.children


def scalar_value(table: StructuralTable, ref: StructuralRef) -> object:
    node = _resolve(table, ref, Kind.VALUE)
    if (node.width is not None or node.children or len(node.payload) != 1
            or type(node.payload[0]) not in (type(None), bool, int, str)):
        raise StructuralIdentityError("invalid owned inventory scalar")
    return node.payload[0]


def matching_effect_rows(
    table: StructuralTable, inventory: StructuralRef, owner: StructuralRef,
    anchor_ea: int, instruction_ea: int, effect_kind: str,
) -> tuple[StructuralRef, ...]:
    """Join owned effect rows against a key issued by the same partition."""
    reference = _resolve(table, owner, Kind.SUBJECT)
    if (reference.width is not None or reference.payload not in (
        ("d810.ir.block_identity", "NativeBlockRef"),
        ("d810.transforms.cfg_transaction", "LogicalBlockRef"),
        ("d810.transforms.cfg_transaction", "PlanBlockRef"),
    )):
        raise StructuralIdentityError("effect join requires an owned block reference")
    if (type(anchor_ea) is not int or type(instruction_ea) is not int
            or type(effect_kind) is not str):
        raise TypeError("effect join coordinates require exact scalars")
    result = []
    for row in sequence_children(table, inventory_field(table, inventory, "effects")):
        node = _resolve(table, row, Kind.SUBJECT)
        if node.payload != (_MODEL_MODULE, "InventoryEffectSite"):
            raise StructuralIdentityError("inventory effects contain a foreign row")
        if record_field(table, row, "owner_ref") is not owner:
            continue
        if (scalar_value(table, record_field(table, row, "owner_anchor_ea")) != anchor_ea
                or scalar_value(table, record_field(table, row, "instruction_ea")) != instruction_ea):
            continue
        kind = _resolve(table, record_field(table, row, "effect_kind"), Kind.ENUM)
        if (kind.width is not None or kind.children or len(kind.payload) != 4
                or kind.payload[:2] != (_MODEL_MODULE, "EffectSiteKind")
                or type(kind.payload[2]) is not str or type(kind.payload[3]) is not str):
            raise StructuralIdentityError("effect row kind is outside the owned schema")
        if kind.payload[3] == effect_kind:
            result.append(row)
    return tuple(result)
