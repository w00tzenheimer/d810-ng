"""Portable semantic graph projection and fingerprinting.

This module is deliberately below both route analysis and unflatten authority.
Only typed ``l/r/d`` instruction operands participate in the graph identity;
the transitional operand manifest is validated for shape, but its values are
not authority data and may be opaque native objects.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
import hashlib
import json

from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import (
    BlockKind,
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.ir.semantics import CallKind, ControlTransferKind, PredicateKind


@dataclass(frozen=True, slots=True)
class MopRecord:
    t: int
    raw_operand_type: int | None
    kind: OperandKind
    size: int
    value: int | None
    stkoff: int | None
    reg: int | None
    block_ref: int | None
    gaddr: int | None
    lvar_off: int | None
    lvar_stkoff: int | None
    switch_cases: tuple[tuple[tuple[int, ...], int], ...]
    stack_refs: tuple[int, ...]
    sub_kind: InsnKind | None
    sub_value_op_kind: ValueOpKind | None
    sub_raw_opcode: int | None
    sub_predicate_kind: PredicateKind | None
    sub_l: MopRecord | None
    sub_r: MopRecord | None
    args: tuple[MopRecord, ...]


@dataclass(frozen=True, slots=True)
class InsnRecord:
    opcode: int
    raw_opcode: int | None
    kind: InsnKind
    ea: int
    native_ea: int | None
    value_op_kind: ValueOpKind | None
    control_transfer_kind: ControlTransferKind | None
    call_kind: CallKind | None
    predicate_kind: PredicateKind | None
    branch_predicate: PredicateKind | None
    compare_width: int | None
    is_conditional_jump: bool
    is_unconditional_jump: bool
    is_call: bool
    l: MopRecord | None  # noqa: E741
    r: MopRecord | None
    d: MopRecord | None
    opcode_attrs: Mapping[str, object]
    display_text_sha256: str


@dataclass(frozen=True, slots=True)
class BlockRecord:
    serial: int
    block_type: int
    raw_block_type: int | None
    kind: BlockKind
    flags: int
    start_ea: int
    native_start_ea: int | None
    succs: tuple[int, ...]
    preds: tuple[int, ...]
    tail_opcode: int | None
    raw_tail_opcode: int | None
    tail_kind: InsnKind | None
    instructions: tuple[InsnRecord, ...]


@dataclass(frozen=True, slots=True)
class GraphRecord:
    func_ea: int
    entry_serial: int
    blocks: tuple[BlockRecord, ...]


def _operand_projection(value: object) -> MopRecord | None:
    if value is None:
        return None
    if type(value) is not MopSnapshot:
        raise TypeError("semantic graph requires MopSnapshot operands")
    return MopRecord(
        value.t, value.raw_operand_type, value.kind, value.size, value.value,
        value.stkoff, value.reg, value.block_ref, value.gaddr, value.lvar_off,
        value.lvar_stkoff, value.switch_cases, value.stack_refs, value.sub_kind,
        value.sub_value_op_kind, value.sub_raw_opcode, value.sub_predicate_kind,
        _operand_projection(value.sub_l), _operand_projection(value.sub_r),
        tuple(_operand_projection(item) for item in value.args),
    )


def _instruction_projection(value: object) -> InsnRecord:
    if type(value) is not InsnSnapshot:
        raise TypeError("semantic graph requires InsnSnapshot instructions")
    return InsnRecord(
        value.opcode, value.raw_opcode, value.kind, value.ea, value.native_ea,
        value.value_op_kind, value.control_transfer_kind, value.call_kind,
        value.predicate_kind, value.branch_predicate, value.compare_width,
        value.is_conditional_jump, value.is_unconditional_jump, value.is_call,
        _operand_projection(value.l), _operand_projection(value.r), _operand_projection(value.d),
        dict(value.opcode_attrs), hashlib.sha256(
            value.display_text.encode("utf-8", errors="replace")
        ).hexdigest(),
    )


def validate_operand_manifest(insn: InsnSnapshot) -> None:
    """Require transitional operand evidence to correspond to typed l/r/d."""

    if type(insn.operands) is not tuple or type(insn.operand_slots) is not tuple:
        raise TypeError("instruction transitional operands must be exact tuples")
    if not insn.operands and not insn.operand_slots:
        return
    if not insn.operands or not insn.operand_slots or len(insn.operands) != len(insn.operand_slots):
        raise ValueError("transitional operands and operand slots must form a complete manifest")
    slot_names = []
    for slot in insn.operand_slots:
        if type(slot) is not tuple or len(slot) != 2 or type(slot[0]) is not str:
            raise ValueError("operand slots must be (name, value) pairs")
        slot_names.append(slot[0])
    if len(set(slot_names)) != len(slot_names) or slot_names != sorted(slot_names, key=("l", "r", "d").index):
        raise ValueError("operand slots must be unique in canonical l/r/d order")
    typed_names = tuple(
        name for name, operand in (("l", insn.l), ("r", insn.r), ("d", insn.d))
        if operand is not None
    )
    if tuple(slot_names) != typed_names:
        raise ValueError("operand slots must exactly match typed l/r/d operands")


def _graph_projection_values(
    func_ea: int,
    entry_serial: int,
    snapshot_blocks: Mapping[int, BlockSnapshot],
) -> GraphRecord:
    block_ids = set(snapshot_blocks)
    if snapshot_blocks and entry_serial not in block_ids:
        raise ValueError("graph entry is not present")
    for serial, block in snapshot_blocks.items():
        if type(block) is not BlockSnapshot or block.serial != serial:
            raise ValueError("graph block mapping key must equal BlockSnapshot.serial")
        if len(set(block.succs)) != len(block.succs) or len(set(block.preds)) != len(block.preds):
            raise ValueError("graph topology must not contain duplicate edges")
        if any(target not in block_ids for target in (*block.succs, *block.preds)):
            raise ValueError("graph topology references an unknown block")
        for target in block.succs:
            if serial not in snapshot_blocks[target].preds:
                raise ValueError("graph topology must be reciprocal")
        for source in block.preds:
            if serial not in snapshot_blocks[source].succs:
                raise ValueError("graph topology must be reciprocal")
        for insn in block.insn_snapshots:
            if type(insn) is not InsnSnapshot:
                raise TypeError("semantic graph requires InsnSnapshot instructions")
            validate_operand_manifest(insn)
    blocks = []
    for serial, block in sorted(snapshot_blocks.items()):
        blocks.append(BlockRecord(
            serial, block.block_type, block.raw_block_type, block.kind, block.flags,
            block.start_ea, block.native_start_ea, block.succs, block.preds,
            block.tail_opcode, block.raw_tail_opcode, block.tail_kind,
            tuple(_instruction_projection(insn) for insn in block.insn_snapshots),
        ))
    return GraphRecord(int(func_ea), int(entry_serial), tuple(blocks))


def portable_graph_projection(
    graph: FlowGraph,
    *,
    blocks: Mapping[int, BlockSnapshot] | None = None,
) -> GraphRecord:
    if type(graph) is not FlowGraph:
        raise TypeError("semantic graph requires FlowGraph")
    snapshot_blocks = graph.blocks if blocks is None else blocks
    return _graph_projection_values(graph.func_ea, graph.entry_serial, snapshot_blocks)


def portable_graph_projection_values(
    func_ea: int,
    entry_serial: int,
    blocks: Mapping[int, BlockSnapshot],
) -> GraphRecord:
    return _graph_projection_values(func_ea, entry_serial, blocks)


def _portable_value(value: object) -> object:
    if value is None or type(value) in (bool, int, str):
        return value
    if isinstance(value, Enum):
        return ("enum", type(value).__qualname__, _portable_value(value.value))
    if is_dataclass(value):
        return (
            "record", type(value).__qualname__,
            tuple(
                (item.name, _portable_value(getattr(value, item.name)))
                for item in fields(value)
                if not item.name.startswith("_")
            ),
        )
    if isinstance(value, Mapping):
        items = tuple(
            (_portable_value(key), _portable_value(item))
            for key, item in value.items()
        )
        return ("mapping", tuple(sorted(items, key=lambda item: json.dumps(item, sort_keys=True))))
    if type(value) is tuple:
        return ("tuple", tuple(_portable_value(item) for item in value))
    if type(value) is list:
        return ("list", tuple(_portable_value(item) for item in value))
    if type(value) is frozenset:
        items = tuple(_portable_value(item) for item in value)
        return ("frozenset", tuple(sorted(items, key=lambda item: json.dumps(item, sort_keys=True))))
    if type(value) is set:
        items = tuple(_portable_value(item) for item in value)
        return ("set", tuple(sorted(items, key=lambda item: json.dumps(item, sort_keys=True))))
    raise TypeError(f"unsupported graph fingerprint value: {type(value).__name__}")


_FINGERPRINT_PREFIX = b"d810-portable-semantic-graph\0unflatten.semantic-flowgraph.v2\0"


def portable_graph_fingerprint(
    graph: FlowGraph,
    *,
    blocks: Mapping[int, BlockSnapshot] | None = None,
) -> str:
    projection = portable_graph_projection(graph, blocks=blocks)
    encoded = json.dumps(
        _portable_value(projection), ensure_ascii=True,
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(_FINGERPRINT_PREFIX + encoded).hexdigest()


def portable_graph_fingerprint_values(
    func_ea: int,
    entry_serial: int,
    blocks: Mapping[int, BlockSnapshot],
) -> str:
    projection = portable_graph_projection_values(func_ea, entry_serial, blocks)
    encoded = json.dumps(
        _portable_value(projection), ensure_ascii=True,
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(_FINGERPRINT_PREFIX + encoded).hexdigest()


__all__ = [
    "BlockRecord", "GraphRecord", "InsnRecord", "MopRecord",
    "portable_graph_fingerprint", "portable_graph_fingerprint_values",
    "portable_graph_projection", "portable_graph_projection_values",
    "validate_operand_manifest",
]
