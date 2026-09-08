"""Local-alias grammar over owned inventory columns, without public row reads.

The private publisher must separately check claim/fact correspondence and export
occurrences. These functions select representation values, not permissions.
"""

import re

from d810.core.structural_identity import StructuralNodeKind as Kind, StructuralRef, StructuralTable
from d810.core.typing import NamedTuple
from d810.transforms.unflatten_authority import inventory_values as values


class LocalAliasInputs(NamedTuple):
    source_owner: StructuralRef
    projected_owner: StructuralRef
    owner_anchor_ea: int
    source_generation: int
    host_ea: int
    host_opcode: int
    value_size: int | None
    native_width: int | None
    alias_token: str
    base_token: str


class LocalAliasRows(NamedTuple):
    source_row: StructuralRef
    source_observation: StructuralRef
    projected_block: StructuralRef
    projected_observation: StructuralRef
    coordinates: tuple[int, int, int, int]
    positions: tuple[int, int, int, int, int]


def _scalar(table, row, name):
    return values.scalar_value(table, values.record_field(table, row, name))


def _enum(table, row, name):
    ref = values.record_field(table, row, name)
    if ref.kind is Kind.VALUE:
        if values.scalar_value(table, ref) is None:
            return None
        raise TypeError("owned inventory optional enum is not None")
    node = table.resolve(ref, Kind.ENUM)
    # Inventory capture stores enum metadata as detached exact scalar values.
    if node.width is not None or node.children or len(node.payload) != 4:
        raise TypeError("owned inventory enum has malformed payload")
    expected = {
        "instruction_kind": ("d810.ir.flowgraph", "InsnKind"),
        "call_kind": ("d810.ir.semantics", "CallKind"),
        "control_transfer_kind": ("d810.ir.semantics", "ControlTransferKind"),
    }.get(name)
    if (expected is None or node.payload[:2] != expected
            or type(node.payload[2]) is not str or type(node.payload[3]) is not str):
        raise TypeError("owned inventory enum schema differs from column")
    return node.payload[3]


def _rows(table, root, field):
    return values.sequence_children(table, values.inventory_field(table, root, field))


def _observations(table, block):
    return values.sequence_children(table, values.record_field(table, block, "instruction_observations"))


def draft_local_alias(
    *, source_table: StructuralTable, source_inventory: StructuralRef,
    projected_table: StructuralTable, projected_inventory: StructuralRef,
    inputs: LocalAliasInputs, allow_route_owned_retirement: bool = False,
) -> LocalAliasRows:
    if type(inputs) is not LocalAliasInputs:
        raise TypeError("owned local alias requires exact input coordinates")
    if (any(type(value) is not int for value in (
            inputs.owner_anchor_ea, inputs.source_generation, inputs.host_ea, inputs.host_opcode,
        )) or any(type(value) not in (int, type(None)) for value in (
            inputs.value_size, inputs.native_width,
        )) or any(type(value) is not str for value in (
            inputs.alias_token, inputs.base_token,
        )) or type(allow_route_owned_retirement) is not bool):
        raise TypeError("owned local alias coordinates require exact scalars")
    if type(source_table) is not StructuralTable or type(projected_table) is not StructuralTable:
        raise TypeError("owned local alias requires exact structural tables")
    if values.scalar_value(source_table, values.inventory_field(source_table, source_inventory, "generation")) != inputs.source_generation:
        raise ValueError("local-alias claim generation mismatch")
    rows = values.matching_effect_rows(
        source_table, source_inventory, inputs.source_owner,
        inputs.owner_anchor_ea, inputs.host_ea, "store",
    )
    if not rows:
        raise ValueError("local-alias source STORE is missing")
    source_row = rows[0]
    if _scalar(source_table, source_row, "opcode") != inputs.host_opcode:
        raise ValueError("local-alias STORE opcode differs from claim")
    owner_serial = _scalar(source_table, source_row, "owner_serial")
    anchor = _scalar(source_table, source_row, "owner_anchor_ea")

    def blocks(table, root, owner):
        table.resolve(owner, Kind.SUBJECT)
        return tuple(row for row in _rows(table, root, "blocks")
                     if values.record_field(table, row, "block_ref") is owner
                     and _scalar(table, row, "serial") == owner_serial
                     and _scalar(table, row, "anchor_ea") == anchor)

    source_blocks = blocks(source_table, source_inventory, inputs.source_owner)
    if len(source_blocks) != 1:
        raise ValueError("local-alias source STORE owner is ambiguous")
    source_observations = tuple(row for row in _observations(source_table, source_blocks[0])
                                if _scalar(source_table, row, "ordinal") == _scalar(source_table, source_row, "instruction_ordinal")
                                and _scalar(source_table, row, "instruction_ea") == inputs.host_ea)
    if len(source_observations) != 1:
        raise ValueError("local-alias source STORE observation is missing")
    source_observation = source_observations[0]
    source_width = _scalar(source_table, source_observation, "width")
    source_opcode = _scalar(source_table, source_observation, "opcode")
    source_raw = _scalar(source_table, source_observation, "raw_opcode")
    if (_enum(source_table, source_observation, "instruction_kind") != "store"
        or source_opcode != _scalar(source_table, source_row, "opcode")
        or source_raw is None
        or source_width != _scalar(source_table, source_row, "width")
        or (inputs.value_size is not None and source_width != inputs.value_size)
        or _scalar(source_table, source_observation, "is_call")
        or _enum(source_table, source_observation, "call_kind") is not None
        or _enum(source_table, source_observation, "control_transfer_kind") is not None):
        raise ValueError("local-alias source STORE observation differs")
    projected_blocks = blocks(projected_table, projected_inventory, inputs.projected_owner)
    if len(projected_blocks) != 1:
        raise ValueError("local-alias projected owner is missing")
    block = projected_blocks[0]
    serial = _scalar(projected_table, block, "serial")
    reachable = tuple(values.scalar_value(projected_table, ref) for ref in _rows(projected_table, projected_inventory, "reachable_serials"))
    if serial not in reachable and not allow_route_owned_retirement:
        raise ValueError("local-alias projected owner is unreachable")
    widths = {width for width in (inputs.value_size, source_width, inputs.native_width)
              if type(width) is int and width > 0}
    observations = tuple(row for row in _observations(projected_table, block)
                         if _scalar(projected_table, row, "instruction_ea") == inputs.host_ea
                         and _scalar(projected_table, row, "width") in widths
                         and _enum(projected_table, row, "instruction_kind") == "mov")
    if len(observations) != 1:
        raise ValueError("local-alias requires one exact MOV observation")
    observation = observations[0]
    opcode = _scalar(projected_table, observation, "opcode")
    if (opcode != inputs.host_opcode or opcode != source_opcode
        or _scalar(projected_table, observation, "raw_opcode") != source_raw
        or _scalar(projected_table, observation, "width") not in widths
        or _scalar(projected_table, observation, "is_call")
        or _enum(projected_table, observation, "call_kind") is not None):
        raise ValueError("local-alias candidate MOV opcode/control differs from claim")
    if _enum(projected_table, observation, "control_transfer_kind") is not None:
        raise ValueError("local-alias candidate MOV has a control transfer")
    display = _scalar(projected_table, observation, "display_text")
    if type(display) is not str:
        raise ValueError("local-alias MOV lacks closed display text")
    grammar = (rf"\s*{re.escape(inputs.alias_token)}\s*=\s*"
               rf"(?:(?i:byte|word|dword|qword)\s+(?i:ptr)\s+)?"
               rf"{re.escape(inputs.base_token)}\s*")
    if re.fullmatch(grammar, display) is None:
        raise ValueError("local-alias MOV does not match closed scalar grammar")
    return LocalAliasRows(source_row, source_observation, block, observation, (
        inputs.host_ea, _scalar(source_table, source_observation, "ordinal"),
        serial, _scalar(projected_table, observation, "ordinal"),
    ), (
        _rows(source_table, source_inventory, "effects").index(source_row),
        _rows(source_table, source_inventory, "blocks").index(source_blocks[0]),
        _observations(source_table, source_blocks[0]).index(source_observation),
        _rows(projected_table, projected_inventory, "blocks").index(block),
        _observations(projected_table, block).index(observation),
    ))
