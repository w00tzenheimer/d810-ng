"""Explicit capture adapters for portable structural values.

This is capture, not semantic admission or a canonical codec. Existing graph
projection validates native snapshots before producing these records. Every
supported record field is enumerated below; schema growth fails closed.
"""

from __future__ import annotations

from dataclasses import fields
from types import MappingProxyType

from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.core.structural_identity import StructuralNodeKind as Kind
from d810.core.structural_identity import StructuralRef, StructuralTable
from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import BlockKind, InsnKind, OperandKind
from d810.ir.graph_fingerprint import BlockRecord, GraphRecord, InsnRecord, MopRecord
from d810.ir.semantics import CallKind, ControlTransferKind, PredicateKind


NATIVE_KEY_FIELDS = (
    "input_identity",
    "processor",
    "bitness",
    "function_rva",
    "function_fingerprint",
    "profile_fingerprint",
    "sdk_fingerprint",
)
# This manifest is also the exact canonical graph projection field inventory.
GRAPH_RECORD_FIELDS = MappingProxyType(
    {
        MopRecord: (
            "t",
            "raw_operand_type",
            "kind",
            "size",
            "value",
            "stkoff",
            "reg",
            "block_ref",
            "gaddr",
            "lvar_off",
            "lvar_stkoff",
            "switch_cases",
            "stack_refs",
            "sub_kind",
            "sub_value_op_kind",
            "sub_raw_opcode",
            "sub_predicate_kind",
            "sub_l",
            "sub_r",
            "args",
        ),
        InsnRecord: (
            "opcode",
            "raw_opcode",
            "kind",
            "ea",
            "native_ea",
            "value_op_kind",
            "control_transfer_kind",
            "call_kind",
            "predicate_kind",
            "branch_predicate",
            "compare_width",
            "is_conditional_jump",
            "is_unconditional_jump",
            "is_call",
            "l",
            "r",
            "d",
            "opcode_attrs",
            "display_text_sha256",
        ),
        BlockRecord: (
            "serial",
            "block_type",
            "raw_block_type",
            "kind",
            "flags",
            "start_ea",
            "native_start_ea",
            "succs",
            "preds",
            "tail_opcode",
            "raw_tail_opcode",
            "tail_kind",
            "instructions",
        ),
        GraphRecord: ("func_ea", "entry_serial", "blocks"),
    }
)
_RECORD_KINDS = MappingProxyType(
    {
        MopRecord: Kind.OPERAND,
        InsnRecord: Kind.INSTRUCTION,
        BlockRecord: Kind.BLOCK,
        GraphRecord: Kind.GRAPH,
    }
)
_ENUM_TYPES = (
    ValueOpKind,
    BlockKind,
    InsnKind,
    OperandKind,
    CallKind,
    ControlTransferKind,
    PredicateKind,
)


def capture_native_key(
    table: StructuralTable, key: NativePreanalysisKey
) -> StructuralRef:
    """Copy all seven validated components without JSON or record hashing."""
    if type(key) is not NativePreanalysisKey:
        raise TypeError("native structural key requires exact NativePreanalysisKey")
    if tuple(f.name for f in fields(NativePreanalysisKey)) != NATIVE_KEY_FIELDS:
        raise TypeError("native structural key schema drift")
    values = tuple(getattr(key, name) for name in NATIVE_KEY_FIELDS)
    # Validate a detached input at admission; never reinitialize the source.
    validated = NativePreanalysisKey(*values)
    if tuple(getattr(validated, name) for name in NATIVE_KEY_FIELDS) != values:
        raise ValueError("native structural key is not normalized")
    return table.intern(
        Kind.NATIVE_KEY, key.bitness, (NativePreanalysisKey.SCHEMA_VERSION, *values), ()
    )


def capture_graph_record(table: StructuralTable, graph: GraphRecord) -> StructuralRef:
    """Capture an already projected graph, detaching nested attribute aliases."""
    if type(graph) is not GraphRecord:
        raise TypeError("structural graph requires exact GraphRecord")
    return _capture(table, graph, set())


def _capture(table: StructuralTable, value: object, active: set[int]) -> StructuralRef:
    value_type = type(value)
    if value_type in (type(None), bool, int, str, bytes):
        return table.intern(Kind.VALUE, None, (value,), ())
    if value_type in _ENUM_TYPES:
        return table.intern(
            Kind.ENUM,
            None,
            (value_type.__module__, value_type.__qualname__, value.name),
            (),
        )
    if id(value) in active:
        raise ValueError("structural capture cycle")
    active.add(id(value))
    try:
        if value_type in GRAPH_RECORD_FIELDS:
            names = GRAPH_RECORD_FIELDS[value_type]
            if tuple(f.name for f in fields(value_type)) != names:
                raise TypeError("structural graph schema drift")
            children = tuple(
                _capture(table, getattr(value, name), active) for name in names
            )
            width = (
                value.size * 8 if value_type is MopRecord and value.size > 0 else None
            )
            return table.intern(_RECORD_KINDS[value_type], width, (), children)
        if value_type in (tuple, list):
            children = tuple(_capture(table, child, active) for child in value)
            return table.intern(Kind.SEQUENCE, None, (value_type.__name__,), children)
        if value_type in (dict, MappingProxyType):
            if any(type(key) is not str for key in value):
                raise TypeError("graph attributes require exact string keys")
            children = tuple(
                _capture(table, item, active)
                for key in sorted(value)
                for item in (key, value[key])
            )
            return table.intern(Kind.MAPPING, None, (), children)
        raise TypeError(f"unsupported structural descendant: {value_type.__name__}")
    finally:
        active.remove(id(value))
