"""Closed canonical encoding and content IDs for unflatten authority data."""

from __future__ import annotations

from collections.abc import Mapping
from contextvars import ContextVar
from d810.core.typing import Protocol
from dataclasses import MISSING, dataclass, fields, is_dataclass
from enum import Enum
import gc
import hashlib
import json
import math
from types import MappingProxyType

from d810.ir.flowgraph import (
    BlockKind,
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    OperandKind,
)
from d810.core.runtime_identity import (
    RUNTIME_CLAIM_SIDECAR_FIELD,
    RUNTIME_SUBJECT_SIDECAR_FIELD,
)
from d810.ir.expressions import ValueOpKind
from d810.ir.semantics import CallKind, ControlTransferKind, PredicateKind
from d810.transforms.cfg_transaction import TransactionAttemptId
from d810.ir.graph_fingerprint import (
    BlockRecord,
    GraphRecord,
    InsnRecord,
    MopRecord,
    portable_graph_fingerprint,
    portable_graph_fingerprint_values,
    portable_graph_projection,
)
from .runtime_authority import transaction_subject_ref
from .canonical_session import (
    active_canonical_session,
    record_bytes_lookup,
    record_canonical_bytes_reuse,
    record_content_id_lookup,
    record_content_id_mint,
    record_content_id_reuse,
    record_deep_validation,
    record_inventory_validation,
    record_materialization,
    record_occurrence_stamp,
    record_roundtrip_decode,
    record_wire_encode,
)

_PREFIX = b"d810-unflatten-authority\0"
SUBJECT_SCHEMA = "unflatten.subject.v1"
CLAIM_SCHEMA = "unflatten.claim.v1"
EVIDENCE_SCHEMA = "unflatten.evidence.v1"
JUSTIFICATION_SCHEMA = "unflatten.justification.v1"
CASE_SCHEMA = "unflatten.case.v1"
RECEIPT_SCHEMA = "unflatten.preparation-receipt.v1"
AUTHORITY_SCHEMA = "unflatten.authority.v1"
BINDING_SCHEMA = "unflatten.binding.v1"
ROUTE_REALIZATION_SCHEMA = "unflatten.route-realization.v1"
SOURCE_ROUTE_AUTHORITY_SCHEMA = "unflatten.source-route-authority.v1"
PROJECTED_ROUTE_ROW_SCHEMA = "unflatten.projected-route-row.v1"
PROJECTED_ROUTE_REALIZATION_SCHEMA = "unflatten.projected-route-realization.v1"
RAW_EFFECT_GATE_PHASE_SCHEMA = "unflatten.raw-effect-gate-phase.v1"
PATCH_STEP_FACT_SCHEMA = "unflatten.patch-step-fact.v1"
PROJECTED_AUTHORITY_SCHEMA = "unflatten.projected-authority.v2"
EFFECT_SITE_COORDINATE_SCHEMA = "unflatten.effect-site-coordinate.v1"
TERMINAL_SITE_COORDINATE_SCHEMA = "unflatten.terminal-site-coordinate.v1"
EXACT_EFFECT_BINDING_SCHEMA = "unflatten.exact-effect-binding.v2"
LOCAL_ALIAS_BINDING_SCHEMA = "unflatten.local-alias-binding.v1"
PROJECTED_EFFECT_SITE_SCHEMA = "unflatten.projected-effect-site.v1"
PROJECTED_TERMINAL_SITE_SCHEMA = "unflatten.projected-terminal-site.v1"
DERIVED_EFFECT_GATE_SCHEMA = "unflatten.derived-effect-gate.v1"
PROJECTED_SEMANTIC_SITE_PHASE_SCHEMA = "unflatten.projected-semantic-sites.v1"
PROJECTED_ROUTE_SITE_PRESERVATION_SCHEMA = "unflatten.projected-route-site-preservation.v1"
SEMANTIC_GRAPH_SCHEMA = "unflatten.semantic-flowgraph.v1"
SEMANTIC_GRAPH_INVENTORY_SCHEMA = "unflatten.semantic-graph-inventory.v1"
DIGEST_FIXTURE_SCHEMA = "digest-fixture.v1"
CLONED_SEMANTIC_OBSERVATION_SCHEMA = "unflatten.cloned-semantic-observation.v1"
CLONED_SEMANTIC_ORIGIN_SCHEMA = "unflatten.cloned-semantic-origin.v1"
CLONED_SEMANTIC_PREFIX_SCHEMA = "unflatten.cloned-semantic-prefix.v1"
_REGISTRIES_READY = False
_ENUM_TYPES: set[type[Enum]] = set()
_RECORD_TYPES: set[type[object]] = set()
_EXTERNAL_TYPES: set[type[object]] = set()
_RECORD_FIELDS: dict[type[object], tuple[str, ...]] = {}
_EXTERNAL_FIELDS: dict[type[object], tuple[str, ...]] = {}
_ENUM_BY_NAME: dict[str, type[Enum]] = {}
_RECORD_BY_NAME: dict[str, type[object]] = {}
_CLAIM_TYPES: set[type[object]] = set()
_EVIDENCE_TYPES: set[type[object]] = set()
_SUBJECT_TYPE: type[object] | None = None
class _DecodedIndexCells:
    __slots__ = ("cells",)

    def __init__(self, cells: tuple[object, ...]) -> None:
        self.cells = cells


@dataclass(frozen=True, slots=True)
class DigestFixture:
    """Fixed conformance record for the canonical wire-format test vector."""

    ea: int
    phase: Enum
    refs: tuple[object, ...]


_PINNED_RECORD_TYPES = (DigestFixture, MopRecord, InsnRecord, BlockRecord, GraphRecord)


def _validate_id(value: object, label: str = "ID") -> str:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:"):
        raise ValueError(f"{label} must be a sha256 ID")
    if any(char not in "0123456789abcdef" for char in value[7:]):
        raise ValueError(f"{label} must be a sha256 ID")
    return value


def _exact_int(value: object, label: str) -> None:
    if type(value) is not int:
        raise TypeError(f"{label} must be an exact int")


def _exact_bool(value: object, label: str) -> None:
    if type(value) is not bool:
        raise TypeError(f"{label} must be an exact bool")


def _optional_int(value: object, label: str) -> None:
    if value is not None:
        _exact_int(value, label)


def _exact_enum(value: object, enum_type: type[Enum], label: str) -> None:
    if type(value) is not enum_type:
        raise TypeError(f"{label} must be {enum_type.__name__}")


def _exact_mappingproxy_backing(value: MappingProxyType) -> dict[str, object]:
    """Return an exact dict proxy backing without invoking mapping callbacks."""
    if type(value) is not MappingProxyType:
        raise TypeError("canonical immutable mapping must be an exact mappingproxy")
    referents = gc.get_referents(value)
    if len(referents) != 1 or type(referents[0]) is not dict:
        raise TypeError("canonical mappingproxy must have an exact dict backing")
    return referents[0]


def _exact_canonical_mapping(value: object) -> dict[str, object]:
    """Accept only exact dicts or exact-dict mapping proxies, callback-free."""
    if type(value) is dict:
        return value
    if type(value) is MappingProxyType:
        return _exact_mappingproxy_backing(value)
    raise TypeError("canonical mappings require an exact dict or mappingproxy")


def _validate_portable_instruction_record(value: object) -> None:
    """Validate the closed portable values reachable from transform proofs."""
    from d810.ir.expressions import Add, And, Const, Load, Move, Mul, Store, Sub
    from d810.ir.instructions import (
        Instruction, InstructionControl, InstructionEffect, InstructionMemoryAccess,
        InstructionMemoryAccessKind, InstructionSwitchCase,
    )
    from d810.ir.locations import AggregateLocation, MemoryCell, RegisterLocation, StackSlot, WeakStackSlot
    from d810.ir.semantics import CallKind, ControlTransferKind, PredicateKind
    from d810.ir.varnode import Space, Varnode
    from d810.ir.value_refs import DefinitionRef, InstructionResultRef, SSAValueRef, TemporaryRef

    def exact_optional_int(item: object, label: str) -> None:
        if item is not None:
            _exact_int(item, label)

    def exact_vn(item: object, label: str) -> None:
        if type(item) is not Varnode:
            raise TypeError(f"{label} must be Varnode")
        _exact_enum(item.space, Space, f"{label}.space")
        _exact_int(item.offset, f"{label}.offset")
        _exact_int(item.size, f"{label}.size")

    def exact_vn_tuple(item: object, label: str) -> None:
        if type(item) is not tuple:
            raise TypeError(f"{label} must be an exact tuple")
        for index, nested in enumerate(item):
            exact_vn(nested, f"{label}[{index}]")

    if type(value) is Varnode:
        exact_vn(value, "Varnode")
    elif type(value) is InstructionSwitchCase:
        if type(value.values) is not tuple:
            raise TypeError("InstructionSwitchCase.values must be an exact tuple")
        for item in value.values:
            _exact_int(item, "InstructionSwitchCase.values item")
        _exact_int(value.target, "InstructionSwitchCase.target")
    elif type(value) is InstructionControl:
        for name, enum_type in (("transfer", __import__("d810.ir.semantics", fromlist=["ControlTransferKind"]).ControlTransferKind), ("predicate", __import__("d810.ir.semantics", fromlist=["PredicateKind"]).PredicateKind), ("call_kind", __import__("d810.ir.semantics", fromlist=["CallKind"]).CallKind)):
            item = getattr(value, name)
            if item is not None:
                _exact_enum(item, enum_type, f"InstructionControl.{name}")
        exact_optional_int(value.target, "InstructionControl.target")
        exact_optional_int(value.fallthrough, "InstructionControl.fallthrough")
        if type(value.switch_cases) is not tuple:
            raise TypeError("InstructionControl.switch_cases must be an exact tuple")
        for item in value.switch_cases:
            if type(item) is not InstructionSwitchCase:
                raise TypeError("InstructionControl.switch_cases item must be InstructionSwitchCase")
            _validate_portable_instruction_record(item)
        for name in ("indirect_target", "call_target", "return_value"):
            item = getattr(value, name)
            if item is not None:
                exact_vn(item, f"InstructionControl.{name}")
        exact_vn_tuple(value.call_args, "InstructionControl.call_args")
    elif type(value) is InstructionEffect:
        _exact_enum(value.kind, __import__("d810.ir.instructions", fromlist=["InstructionEffectKind"]).InstructionEffectKind, "InstructionEffect.kind")
        for name in ("target", "segment", "value"):
            item = getattr(value, name)
            if item is not None:
                exact_vn(item, f"InstructionEffect.{name}")
        exact_vn_tuple(value.args, "InstructionEffect.args")
    elif type(value) is InstructionMemoryAccess:
        _exact_enum(value.kind, InstructionMemoryAccessKind, "InstructionMemoryAccess.kind")
        for name in ("target", "segment", "value"):
            item = getattr(value, name)
            if item is not None:
                exact_vn(item, f"InstructionMemoryAccess.{name}")
        exact_optional_int(value.width, "InstructionMemoryAccess.width")
    elif type(value) is Instruction:
        if type(value.operation) not in {ValueOpKind, PredicateKind, ControlTransferKind, CallKind}:
            raise TypeError("Instruction.operation must be a closed operation enum")
        exact_vn_tuple(value.inputs, "Instruction.inputs")
        if value.result is not None:
            exact_vn(value.result, "Instruction.result")
        if type(value.effects) is not tuple or any(type(item) is not InstructionEffect for item in value.effects):
            raise TypeError("Instruction.effects must contain exact InstructionEffect values")
        for item in value.effects:
            _validate_portable_instruction_record(item)
        if value.control is not None:
            if type(value.control) is not InstructionControl:
                raise TypeError("Instruction.control must be InstructionControl or None")
            _validate_portable_instruction_record(value.control)
        if value.memory is not None:
            if type(value.memory) is not InstructionMemoryAccess:
                raise TypeError("Instruction.memory must be InstructionMemoryAccess or None")
            _validate_portable_instruction_record(value.memory)
        attrs = _exact_canonical_mapping(value.attrs)
        for key, item in dict.items(attrs):
            if type(key) is not str:
                raise TypeError("Instruction.attrs keys must be exact str")
            _validate_canonical_value(item)
        if type(value.input_exprs) is not tuple or type(value.operand_expr_fragments) is not tuple:
            raise TypeError("Instruction expression fields must be exact tuples")
        for item in (*value.input_exprs, *value.operand_expr_fragments):
            if item is not None:
                _validate_canonical_value(item)
    elif type(value) in (Const, Move, Add, And, Load, Mul, Store, Sub):
        if type(value) is Const:
            _exact_int(value.value, "Const.value")
        elif type(value) is Move:
            _validate_canonical_value(value.source)
        elif type(value) in (Add, And, Mul, Sub):
            _validate_canonical_value(value.left)
            _validate_canonical_value(value.right)
        elif type(value) is Load:
            _validate_canonical_value(value.address)
        else:
            _validate_canonical_value(value.address)
            _validate_canonical_value(value.value)
    elif type(value) is DefinitionRef:
        _validate_canonical_value(value.location)
        _exact_int(value.version, "DefinitionRef.version")
    elif type(value) is InstructionResultRef:
        _exact_int(value.insn, "InstructionResultRef.insn")
        _exact_int(value.result_index, "InstructionResultRef.result_index")
    elif type(value) is SSAValueRef:
        _exact_int(value.value_id, "SSAValueRef.value_id")
    elif type(value) is TemporaryRef:
        _exact_int(value.temp_id, "TemporaryRef.temp_id")
    elif type(value) in (StackSlot, RegisterLocation, MemoryCell, WeakStackSlot):
        for name in ("offset", "size") if type(value) is StackSlot else ("register_id", "size") if type(value) is RegisterLocation else ("address", "size") if type(value) is MemoryCell else ("size",):
            _exact_int(getattr(value, name), f"{type(value).__name__}.{name}")
    elif type(value) is AggregateLocation:
        if type(value.members) is not tuple:
            raise TypeError("AggregateLocation.members must be an exact tuple")
        for item in value.members:
            _validate_canonical_value(item)


def _exact_tuple(value: object, label: str) -> tuple[object, ...]:
    if type(value) is not tuple:
        raise TypeError(f"{label} must be an exact tuple")
    return value


def _sha256_hex(value: object, label: str) -> None:
    if type(value) is not str or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError(f"{label} must be lowercase SHA-256 hex")


def _validate_canonical_value(value: object, seen: set[int] | None = None) -> None:
    """Validate values reachable from pinned records without coercion."""

    seen = set() if seen is None else seen
    if value is None or type(value) in (bool, int, str, bytes):
        return
    if isinstance(value, Enum):
        _ensure_registries()
        if type(value) not in _ENUM_TYPES:
            raise TypeError(f"unregistered enum type: {type(value).__name__}")
        return
    if type(value) is dict or type(value) is MappingProxyType:
        mapping = _exact_canonical_mapping(value)
        marker = id(value)
        if marker in seen:
            raise ValueError("cyclic canonical mapping")
        seen.add(marker)
        try:
            for key, item in dict.items(mapping):
                if type(key) is not str:
                    raise TypeError("canonical mappings require string keys")
                _validate_canonical_value(item, seen)
        finally:
            seen.remove(marker)
        return
    if isinstance(value, Mapping):
        raise TypeError("canonical mappings require an exact dict or mappingproxy")
    if type(value) in (list, tuple, frozenset):
        marker = id(value)
        if marker in seen:
            raise ValueError("cyclic canonical value")
        seen.add(marker)
        for item in value:
            _validate_canonical_value(item, seen)
        seen.remove(marker)
        return
    if type(value) in _PINNED_RECORD_TYPES:
        _validate_pinned_record(value, seen)
        return
    _ensure_registries()
    # Binder-owned route records are encode-only, but canonical encoding must
    # still revalidate their sealed cross-field identity.  A forged object
    # created with ``object.__new__`` can otherwise satisfy the field walker
    # while carrying a stale relation/prefix/origin ID.
    if (
        type(value).__module__ == "d810.transforms.unflatten_authority.model"
        and type(value).__name__ in {
            "ClonedSemanticInstructionOrigin", "ClonedSemanticPrefix",
            "FoldedConditionalRouteRealization",
            "TwoArmDirectBranchRouteRealization",
            "BranchFallthroughHelperRouteRealization",
            "RetainedPrefixRouteRealization",
            "SharedCarrierSourceBypassRouteRealization",
            "ClonedRouteCorridorRealization",
            "ClonedCarrierRouteCorridorRealization",
        }
    ):
        value.__post_init__()
    if type(value).__module__.startswith("d810.ir."):
        _validate_portable_instruction_record(value)
    if type(value) in _RECORD_TYPES or type(value) in _EXTERNAL_TYPES:
        marker = id(value)
        if marker in seen:
            raise ValueError("cyclic registered record")
        seen.add(marker)
        try:
            for name in _RECORD_FIELDS.get(type(value), _EXTERNAL_FIELDS.get(type(value), ())):
                item = type(value).SCHEMA_VERSION if type(value).__name__ == "NativePreanalysisKey" and name == "schema_version" else getattr(value, name)
                if type(value).__name__ in {"PreparationBuildMetrics", "PhaseBuildMetrics"} and name == "inventory_ms":
                    if type(item) not in (int, float) or not math.isfinite(float(item)):
                        raise ValueError("invalid preparation metric")
                elif type(value).__name__ == "GenericEntryGateFacts" and name in {"retained_ratio", "min_retained_ratio"}:
                    if type(item) is not float or not math.isfinite(item):
                        raise ValueError("invalid generic gate ratio")
                else:
                    _validate_canonical_value(item, seen)
        finally:
            seen.remove(marker)
        return
    raise TypeError(f"no canonical encoding for {type(value).__name__}")


def _validate_pinned_record(value: object, seen: set[int] | None = None) -> None:
    """Fail-closed runtime schema validators for the five graph wire records."""

    seen = set() if seen is None else seen
    marker = id(value)
    if marker in seen:
        raise ValueError("cyclic pinned record")
    seen.add(marker)
    try:
        if type(value) is DigestFixture:
            _exact_int(value.ea, "DigestFixture.ea")
            from d810.transforms.unflatten_authority import model
            _exact_enum(value.phase, model.UnflattenAuthorityPhase, "DigestFixture.phase")
            refs = _exact_tuple(value.refs, "DigestFixture.refs")
            for item in refs:
                _validate_canonical_value(item, seen)
            return
        if type(value) is MopRecord:
            _exact_int(value.t, "MopRecord.t")
            _optional_int(value.raw_operand_type, "MopRecord.raw_operand_type")
            _exact_enum(value.kind, OperandKind, "MopRecord.kind")
            _exact_int(value.size, "MopRecord.size")
            for name in ("value", "stkoff", "reg", "block_ref", "gaddr", "lvar_off", "lvar_stkoff", "sub_raw_opcode"):
                _optional_int(getattr(value, name), f"MopRecord.{name}")
            switch_cases = _exact_tuple(value.switch_cases, "MopRecord.switch_cases")
            for case in switch_cases:
                if type(case) is not tuple or len(case) != 2:
                    raise TypeError("MopRecord.switch_cases entries must be pairs")
                case_values = _exact_tuple(case[0], "MopRecord.switch_cases values")
                for item in case_values:
                    _exact_int(item, "MopRecord.switch_cases value")
                _exact_int(case[1], "MopRecord.switch_cases target")
            stack_refs = _exact_tuple(value.stack_refs, "MopRecord.stack_refs")
            for item in stack_refs:
                _exact_int(item, "MopRecord.stack_refs item")
            for name, enum_type in (("sub_kind", InsnKind), ("sub_value_op_kind", ValueOpKind), ("sub_predicate_kind", PredicateKind)):
                item = getattr(value, name)
                if item is not None:
                    _exact_enum(item, enum_type, f"MopRecord.{name}")
            for name in ("sub_l", "sub_r"):
                item = getattr(value, name)
                if item is not None:
                    if type(item) is not MopRecord:
                        raise TypeError(f"MopRecord.{name} must be MopRecord or None")
                    _validate_pinned_record(item, seen)
            args = _exact_tuple(value.args, "MopRecord.args")
            for item in args:
                if type(item) is not MopRecord:
                    raise TypeError("MopRecord.args must contain MopRecord values")
                _validate_pinned_record(item, seen)
            return
        if type(value) is InsnRecord:
            _exact_int(value.opcode, "InsnRecord.opcode")
            _optional_int(value.raw_opcode, "InsnRecord.raw_opcode")
            _exact_enum(value.kind, InsnKind, "InsnRecord.kind")
            _exact_int(value.ea, "InsnRecord.ea")
            _optional_int(value.native_ea, "InsnRecord.native_ea")
            for name, enum_type in (("value_op_kind", ValueOpKind), ("control_transfer_kind", ControlTransferKind), ("call_kind", CallKind), ("predicate_kind", PredicateKind), ("branch_predicate", PredicateKind)):
                item = getattr(value, name)
                if item is not None:
                    _exact_enum(item, enum_type, f"InsnRecord.{name}")
            _optional_int(value.compare_width, "InsnRecord.compare_width")
            for name in ("is_conditional_jump", "is_unconditional_jump", "is_call"):
                _exact_bool(getattr(value, name), f"InsnRecord.{name}")
            for name in ("l", "r", "d"):
                item = getattr(value, name)
                if item is not None:
                    if type(item) is not MopRecord:
                        raise TypeError(f"InsnRecord.{name} must be MopRecord or None")
                    _validate_pinned_record(item, seen)
            if type(value.opcode_attrs) is not MappingProxyType:
                raise TypeError(
                    "InsnRecord.opcode_attrs must be an exact mappingproxy"
                )
            _validate_canonical_value(value.opcode_attrs, seen)
            _sha256_hex(value.display_text_sha256, "InsnRecord.display_text_sha256")
            return
        if type(value) is BlockRecord:
            _exact_int(value.serial, "BlockRecord.serial")
            _exact_int(value.block_type, "BlockRecord.block_type")
            _optional_int(value.raw_block_type, "BlockRecord.raw_block_type")
            _exact_enum(value.kind, BlockKind, "BlockRecord.kind")
            _exact_int(value.flags, "BlockRecord.flags")
            _exact_int(value.start_ea, "BlockRecord.start_ea")
            _optional_int(value.native_start_ea, "BlockRecord.native_start_ea")
            for name in ("succs", "preds"):
                items = _exact_tuple(getattr(value, name), f"BlockRecord.{name}")
                for item in items:
                    _exact_int(item, f"BlockRecord.{name} item")
            _optional_int(value.tail_opcode, "BlockRecord.tail_opcode")
            _optional_int(value.raw_tail_opcode, "BlockRecord.raw_tail_opcode")
            if value.tail_kind is not None:
                _exact_enum(value.tail_kind, InsnKind, "BlockRecord.tail_kind")
            instructions = _exact_tuple(value.instructions, "BlockRecord.instructions")
            for item in instructions:
                if type(item) is not InsnRecord:
                    raise TypeError("BlockRecord.instructions must contain InsnRecord values")
                _validate_pinned_record(item, seen)
            return
        if type(value) is GraphRecord:
            _exact_int(value.func_ea, "GraphRecord.func_ea")
            _exact_int(value.entry_serial, "GraphRecord.entry_serial")
            blocks = _exact_tuple(value.blocks, "GraphRecord.blocks")
            serials = []
            by_serial = {}
            for item in blocks:
                if type(item) is not BlockRecord:
                    raise TypeError("GraphRecord.blocks must contain BlockRecord values")
                _validate_pinned_record(item, seen)
                serials.append(item.serial)
                by_serial[item.serial] = item
            if serials != sorted(serials) or len(set(serials)) != len(serials):
                raise ValueError("GraphRecord.blocks must be sorted and unique")
            if blocks and value.entry_serial not in by_serial:
                raise ValueError("GraphRecord.entry_serial must be present")
            for serial, block in by_serial.items():
                if len(set(block.succs)) != len(block.succs) or len(set(block.preds)) != len(block.preds):
                    raise ValueError("GraphRecord topology must not contain duplicate edges")
                for target in (*block.succs, *block.preds):
                    if target not in by_serial:
                        raise ValueError("GraphRecord topology references unknown block")
                for target in block.succs:
                    if serial not in by_serial[target].preds:
                        raise ValueError("GraphRecord topology must be reciprocal")
                for source in block.preds:
                    if serial not in by_serial[source].succs:
                        raise ValueError("GraphRecord topology must be reciprocal")
            return
    finally:
        seen.remove(marker)


def _ensure_registries() -> None:
    global _REGISTRIES_READY
    if _REGISTRIES_READY:
        return
    from d810.analyses.control_flow import semantic_route_evidence as route
    from d810.core.native_preanalysis_key import NativePreanalysisKey
    from d810.ir.block_identity import NativeEaInterval, NativeEaIntervalSet, StableBlockIdentity
    from d810.ir.expressions import Add, And, Const, Load, Move, Mul, Store, Sub, ValueOpKind
    from d810.ir.semantics import CallKind, ControlTransferKind, PredicateKind
    from d810.ir.semantic_edge import SemanticEdgeRole
    from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
    from d810.ir.instructions import (
        Instruction, InstructionControl, InstructionEffect, InstructionEffectKind,
        InstructionEffectSite, InstructionMemoryAccess, InstructionMemoryAccessKind,
        InstructionSwitchCase,
    )
    from d810.ir.varnode import Space, Varnode
    from d810.ir.value_refs import DefinitionRef, InstructionResultRef, SSAValueRef, TemporaryRef
    from d810.ir.locations import AggregateLocation, MemoryCell, RegisterLocation, StackSlot, WeakStackSlot
    from d810.analyses.control_flow.terminal_return_carrier_evidence import (
        TerminalReturnCarrierEvidence,
        TerminalReturnCarrierSource,
        TerminalReturnCarrierSourceKind,
    )
    from d810.analyses.control_flow.materialized_indirect_transfer import TerminalReturnCarrierRequest
    from d810.transforms.cfg_transaction import (
        LogicalBlockRef, NativeBlockRef, PlanBlockRef, TransactionAttemptId,
        PatchStepKind,
    )
    from d810.transforms.plan import PatchBlockSpec, PatchEdgeRef
    from d810.transforms.graph_modification import (
        PreserveLivePredicateCondition,
        SyntheticCounterBoundCondition,
        SyntheticRegisterNonzeroCondition,
        SyntheticStackValueEqualsCondition,
    )
    from d810.transforms.unflatten_authority import model
    from d810.transforms.unflatten_authority import gates

    _ENUM_TYPES.update({
        model.UnflattenAuthorityPhase, model.SemanticSubjectKind, model.SemanticSubjectRole,
        model.SafetyDimension, model.EvidencePolarity, model.ObligationState,
        model.SubjectBindingStatus, model.SemanticLossKind, model.UnflattenClaimKind, model.ProviderConsensusMode,
        model.StructuralDisposition, model.EffectSiteKind, model.TerminalKind,
        model.ProjectedSiteLineageKind,
        model.ProjectedEffectSiteOutcome, model.ProjectedTerminalSiteOutcome,
        model.CorridorPathDisposition,
        model.GenericCfgGateKind, model.AuthorityEvidenceKind, model.UnflattenJustificationRule,
        model.UnflattenAuthorityReason, model.UnflattenPlanRoute, model.UnflattenPlanShape,
        model.TopologyIncidenceKind,
        model.RetirementPhaseClassification,
        model.RouteRealizationKind, model.RouteRealizationFailureStage,
        model.RouteRealizationFailureScope,
    })
    _ENUM_TYPES.update({
        ValueOpKind, CallKind, ControlTransferKind, PredicateKind,
        SemanticEdgeRole, Space, InstructionEffectKind, InstructionMemoryAccessKind,
        BlockKind, InsnKind, OperandKind,
            StorageIdentityKind, route.SemanticRouteShape, route.SemanticRouteProofKind,
            route.SemanticPredicateKind, route.SemanticStateWriteDeliveryKind,
            route.SemanticPhysicalWriteByteOrder,
            route.SemanticDagEndpointKind,
        InstructionEffectKind,
        TerminalReturnCarrierSourceKind,
        PatchStepKind, model.EntryEndpointLivenessReason,
    })
    model_records = (
        model.BlockSubjectLocator, model.LogicalFunctionExitSubjectLocator,
        model.ObservedLogicalEndpointOccurrence,
        model.ObservedRouteTopologyOccurrence,
        model.ObservedLoweredConditionalTopologyOccurrence,
        model.EdgeSubjectLocator, model.RouteSubjectLocator,
        model.EffectSubjectLocator, model.HandlerSubjectLocator, model.TerminalSubjectLocator,
        model.ValueFlowSubjectLocator, model.CorridorSubjectLocator, model.SemanticSubjectRef,
        model.CorridorCoveragePathNode, model.CorridorSemanticExclusion,
        model.DefaultGapInitialStateSeed, model.DefaultGapInfeasibilityExclusion,
        model.DefaultGapInfeasibilityPath, model.DefaultGapInfeasibilityForecast,
        model.CorridorCoveragePath, model.CorridorCoverageForecast,
        model.CorridorSemanticExclusionCorrelation, model.DefaultGapInfeasibilityCorrelation,
        model.CorridorCoveragePhaseResult, model.DefaultGapInfeasibilityPhaseResult,
        model.DetachedDeadHandlerComponentPhaseResult,
        model.DetachedDeadHandlerComponentSourceResult,
        model.DetachedComponentEvidencePayload,
        model.TerminalCyclePhaseResult,
        model.PhaseSubjectBinding, model.PhaseBindingEvidencePayload, model.TopologyEdgeRelation, model.TopologyEvidencePayload,
        model.StructuralLineageEvidencePayload, model.SemanticRouteEvidencePayload,
        model.EffectSiteEvidencePayload, model.ReachabilityEvidencePayload,
        model.UseDefAuditEvidencePayload, model.CorridorCoverageEvidencePayload,
        model.TerminalCycleEvidencePayload,
        model.PatchStepEvidencePayload, model.GenericCfgGateEvidencePayload, model.AuthorityEvidence,
        model.GenericCfgGateResult, model.ProviderConsensusWitness,
        model.RetiredDispatcherInfrastructureClaim, model.DetachedDeadHandlerComponentClaim, model.EquivalentSemanticRouteClaim,
        model.ExactInfeasibleEffectClaim, model.LocalAliasEffectScalarizationClaim,
        model.TerminalCycleBreakClaim, model.UseDefFragmentWitness, model.SourceBlockIdentityWitness,
        model.EntryEndpointLivenessForecast, model.EntryEndpointLivenessAllowance, model.BoundEntryEndpointLivenessAllowance,
        model.SourceIdentityCatalog, model.AuthoritativeHandlerInput,
        model.RetirementPlanMember, model.DispatcherRetirementCandidate,
        model.RetirementCandidateCatalog, model.RetirementPhaseMember,
        model.RetirementPhaseResult,
        model.UnflattenPlanInputCatalog, model.ProposedUnflattenContract,
        model.ConditionalSubjectRelation, model.PreparationAuthorityReceipt,
        model.ObligationKey, model.AuthorityJustification, model.ObligationEvidenceCell,
        model.ObligationEvidenceIndex, model.FailedObligation, model.PreparationBuildMetrics,
        model.SemanticLossRow, model.SemanticLossLedger, model.ObservedSemanticLossDelta,
        model.SemanticPhaseMetrics,
        model.PhaseBuildMetrics, model.InventoryPredicateObservation,
        model.InventoryInstructionObservation,
        model.InventoryBlockObservation,
        model.InventoryEffectSite, model.InventoryTerminalSite,
        model.InventoryTopologyIncidence, model.SemanticGraphInventory,
        model.DerivedUnflattenPreparationInputs, model.SemanticSafetyCase,
        model.UnflattenAuthorityVerdict,
        model.AnchoredBlockRef, model.EffectSiteCoordinate, model.TerminalSiteCoordinate,
        model.RawEffectGatePhaseFact, model.RouteRealizationFailure, model.RouteRealizationFailureScope, model.ConditionalRoleCoordinate,
        model.ScalarizedInstructionCoordinate, model.ExactEffectBindingResult,
        model.LocalAliasScalarizationBindingResult, model.ProjectedEffectSiteResult,
        model.ProjectedTerminalSiteResult, model.ProjectedSemanticSitePhaseResult,
        model.ProjectedRouteSitePreservation,
        model.RealizedConditionalArm, model.DirectRouteRealization,
        model.SharedCarrierSourceBypassRouteRealization,
        model.RetainedPrefixRouteRealization,
        model.LoweredConditionalRouteRealization, model.ClonedConditionalRouteRealization,
        model.FoldedConditionalRouteRealization,
        model.ClonedSemanticInstructionOrigin, model.ClonedSemanticPrefix,
        model.TwoArmDirectBranchRouteRealization, model.BranchFallthroughHelperRouteRealization,
        model.ClonedRouteCorridorRealization,
        model.ClonedCarrierRouteCorridorRealization,
        model.SourceBoundRouteAuthority,
        model.ProjectedRouteRealizationRow, model.ProjectedRouteRealization,
        model.SourceBoundRouteAuthorityAccepted, model.SourceBoundRouteAuthorityRejected,
        model.ProjectedRouteRealizationAccepted, model.ProjectedRouteRealizationRejected,
    )
    _RECORD_TYPES.update({DigestFixture, MopRecord, InsnRecord, BlockRecord, GraphRecord, *model_records})
    _CLAIM_TYPES.update({
        model.RetiredDispatcherInfrastructureClaim,
        model.DetachedDeadHandlerComponentClaim,
        model.EquivalentSemanticRouteClaim,
        model.ExactInfeasibleEffectClaim,
        model.LocalAliasEffectScalarizationClaim,
        model.TerminalCycleBreakClaim,
    })
    _EVIDENCE_TYPES.add(model.AuthorityEvidence)
    global _SUBJECT_TYPE
    _SUBJECT_TYPE = model.SemanticSubjectRef
    _RECORD_FIELDS.update({
        DigestFixture: ("ea", "phase", "refs"),
        MopRecord: ("t", "raw_operand_type", "kind", "size", "value", "stkoff", "reg", "block_ref", "gaddr", "lvar_off", "lvar_stkoff", "switch_cases", "stack_refs", "sub_kind", "sub_value_op_kind", "sub_raw_opcode", "sub_predicate_kind", "sub_l", "sub_r", "args"),
        InsnRecord: ("opcode", "raw_opcode", "kind", "ea", "native_ea", "value_op_kind", "control_transfer_kind", "call_kind", "predicate_kind", "branch_predicate", "compare_width", "is_conditional_jump", "is_unconditional_jump", "is_call", "l", "r", "d", "opcode_attrs", "display_text_sha256"),
        BlockRecord: ("serial", "block_type", "raw_block_type", "kind", "flags", "start_ea", "native_start_ea", "succs", "preds", "tail_opcode", "raw_tail_opcode", "tail_kind", "instructions"),
        GraphRecord: ("func_ea", "entry_serial", "blocks"),
        model.BlockSubjectLocator: ("block_ref", "anchor_ea"),
        model.LogicalFunctionExitSubjectLocator: ("block_ref", "serial"),
        model.ObservedLogicalEndpointOccurrence: (
            "logical_ref",
            "projected_serial",
            "observed_serial",
            "owner_ref",
            "predecessor_refs",
        ),
        model.ObservedRouteTopologyOccurrence: (
            "relation_id", "row_id", "patch_fact", "normalized_pairs",
        ),
        model.ObservedLoweredConditionalTopologyOccurrence: (
            "patch_fact", "source_ref", "false_target_ref", "true_target_ref",
            "normalized_pairs",
        ),
        model.EdgeSubjectLocator: ("source_ref", "source_anchor_ea", "target_ref", "target_anchor_ea", "edge_role"),
        model.RouteSubjectLocator: ("proof_id", "atomic_group_id", "source_ref", "source_anchor_ea", "destination_locators", "dag_endpoint_locators"),
        model.EffectSubjectLocator: ("owner_ref", "owner_anchor_ea", "instruction_ea", "effect_kind"),
        model.HandlerSubjectLocator: ("block_ref", "anchor_ea", "normalized_states"),
        model.TerminalSubjectLocator: ("block_ref", "anchor_ea", "terminal_kind", "instruction_ea"),
        model.ValueFlowSubjectLocator: ("fragment_id", "state_identity", "redirect_owner_refs"),
        model.CorridorSubjectLocator: ("corridor_id", "entry_ref", "entry_anchor_ea", "member_refs", "member_anchor_eas"),
        model.CorridorCoveragePathNode: ("block_ref", "anchor_ea"),
        model.CorridorSemanticExclusion: ("exclusion_id", "digest", "normalized_state", "state_identity", "source", "feeder", "prefix", "root"),
        model.DefaultGapInitialStateSeed: ("normalized_state", "route_proof_id"),
        model.DefaultGapInfeasibilityExclusion: ("exclusion_id", "digest", "state_width_bytes", "state_identity", "dispatcher", "default_entry", "residual", "initial_state_seeds", "route_proof_ids", "normalized_reachable_states"),
        model.DefaultGapInfeasibilityPath: ("path_id", "nodes", "state_merge", "exclusion_id"),
        model.DefaultGapInfeasibilityForecast: ("extension_id", "base_forecast", "paths", "exclusion_digests", "exclusions"),
        model.CorridorCoveragePath: ("path_id", "nodes", "state_merge", "disposition", "semantic_exclusion_ids"),
        model.CorridorCoverageForecast: ("forecast_id", "plan_id", "function_ea", "source_native_key", "source_generation", "dispatcher_ref", "dispatcher_anchor_ea", "paths", "covered_path_ids", "residual_path_ids", "enumeration_complete", "semantic_exclusion_digests", "semantic_exclusions", "semantic_exclusion_path_ids"),
        model.CorridorSemanticExclusionCorrelation: ("exclusion_id", "exclusion_digest", "path_id", "claim_id", "proof_id", "ordered_prefix", "source_fingerprint", "candidate_fingerprint", "source_generation", "candidate_generation", "phase_result_id"),
        model.DefaultGapInfeasibilityCorrelation: ("exclusion_id", "exclusion_digest", "path_id", "dispatcher", "default_entry", "residual", "initial_state_seeds", "route_proof_ids", "normalized_reachable_states", "source_fingerprint", "candidate_fingerprint", "source_generation", "candidate_generation", "phase_result_id"),
            model.CorridorCoveragePhaseResult: ("result_id", "forecast_id", "phase", "source_fingerprint", "candidate_fingerprint", "source_generation", "candidate_generation", "covered_path_ids", "residual_path_ids", "drifted_path_ids", "enumeration_complete", "matched_semantic_exclusion_ids", "source_dispatcher_reachable", "candidate_dispatcher_reachable", "semantic_exclusion_correlations", "comparison_region_subject_ids", "dispatcher_subject_id"),
        model.DefaultGapInfeasibilityPhaseResult: ("result_id", "base_result", "forecast", "phase", "source_fingerprint", "candidate_fingerprint", "source_generation", "candidate_generation", "matched_exclusion_ids", "correlations"),
            model.DetachedDeadHandlerComponentSourceResult: ("result_id", "claim_id", "corridor_forecast_id", "corridor_coverage_result_id", "source_fingerprint", "source_generation", "dispatcher_subject_id", "dispatcher_block_ref", "dead_handler_subject_ids", "retained_handler_subject_ids", "component_subject_ids", "comparison_region_subject_ids", "source_reachable_subject_ids", "dead_handler_block_refs", "retained_handler_block_refs", "comparison_region_block_refs", "terminal_digest", "effect_digest", "topology_digest", "source_reachable_block_refs", "component_block_refs", "remainder_block_refs", "terminal_site_keys", "effect_site_keys", "source_blocks"),
            model.DetachedDeadHandlerComponentPhaseResult: ("result_id", "claim_id", "phase", "corridor_coverage_result_id", "source_fingerprint", "candidate_fingerprint", "source_generation", "candidate_generation", "accepted", "source_result_id"),
            model.DetachedComponentEvidencePayload: ("phase_result_id", "claim_id", "corridor_coverage_result_id", "phase", "source_fingerprint", "candidate_fingerprint", "source_generation", "candidate_generation", "accepted", "authorized_subject_ids"),
            model.TerminalCyclePhaseResult: ("result_id", "claim_id", "terminal_route_proof_id", "phase", "source_fingerprint", "candidate_fingerprint", "source_generation", "candidate_generation", "bound_subject_ids", "source_binding_digest", "candidate_binding_digest", "residue_refs", "source_cycle_edges", "candidate_cycle_edges", "source_bindings", "candidate_bindings", "terminal_source_ref", "cleanup_source_ref", "terminal_carrier_ref", "terminal_route_refs", "terminal_subject_id", "terminal_subject_ref"),
        model.SemanticSubjectRef: ("kind", "role", "subject_id", "block_ref", "anchor_ea", "locator"),
        model.PhaseSubjectBinding: (
            "subject", "phase", "block_ref", "graph_fingerprint", "generation",
            "status", "serial", "anchor_ea", "native_instruction_eas", "role",
            "observed_logical_occurrence",
        ),
        model.PhaseBindingEvidencePayload: ("binding",),
        model.TopologyEdgeRelation: ("role", "source_subject_id", "target_subject_id", "native_edge_anchor_ea"),
        model.TopologyEvidencePayload: ("subject_id", "predecessor_subject_ids", "successor_subject_ids", "reciprocal_edges", "expected_shape_digest", "candidate_shape_digest", "expected_edge_relations", "candidate_edge_relations"),
        model.StructuralLineageEvidencePayload: ("source_subject_id", "candidate_subject_ids", "disposition", "reciprocal_native_origin_eas", "claim_id", "source_subject_ids"),
        model.SemanticRouteEvidencePayload: ("route_subject_id", "proof_ids", "atomic_group_id", "source_subject_id", "destination_subject_ids", "matched", "dag_endpoint_subject_ids"),
        model.EffectSiteEvidencePayload: ("effect_subject_id", "effect_kind", "instruction_ea", "opcode", "width", "storage_identity", "normalized_state", "provider_mode", "provider_ids", "preserved"),
        model.ReachabilityEvidencePayload: ("root_subject_id", "target_subject_id", "reachable", "path_subject_ids"),
        model.UseDefAuditEvidencePayload: ("fragment_id", "state_identity", "executed", "fragment_atomic", "actionable_non_state_severance_count", "violation_ids"),
        model.CorridorCoverageEvidencePayload: ("corridor_subject_id", "forecast_id", "phase_result_id", "covered_path_ids", "residual_path_ids", "drifted_path_ids", "enumeration_complete", "matched_semantic_exclusion_ids", "source_dispatcher_reachable", "candidate_dispatcher_reachable"),
        model.TerminalCycleEvidencePayload: ("phase_result_id", "claim_id", "terminal_route_proof_id", "phase", "source_fingerprint", "candidate_fingerprint", "source_generation", "candidate_generation", "bound_subject_ids", "source_binding_digest", "candidate_binding_digest", "residue_refs", "source_cycle_edges", "candidate_cycle_edges", "source_bindings", "candidate_bindings", "terminal_source_ref", "cleanup_source_ref", "terminal_carrier_ref", "terminal_route_refs", "terminal_subject_id", "terminal_subject_ref"),
        model.PatchStepEvidencePayload: ("plan_id", "step_index", "step_type", "owner_ref", "step_digest", "host_ea", "host_opcode", "value_size", "creation_spec_digest"),
        model.GenericCfgGateEvidencePayload: ("gate", "passed", "affected_subject_ids", "reason_code"),
        model.AuthorityEvidence: ("evidence_id", "kind", "subject", "phase", "payload"),
        model.GenericCfgGateResult: ("gate", "passed", "supported_subject_ids", "refuted_subject_ids", "reason_code"),
        model.ProviderConsensusWitness: ("mode", "provider_ids"),
        model.RetiredDispatcherInfrastructureClaim: ("claim_id", "kind", "infrastructure_subject", "corridor_subject", "member_subjects", "candidate_evidence_ids", "source_generation", "candidate_catalog"),
        model.DetachedDeadHandlerComponentClaim: ("claim_id", "kind", "dispatcher_subject", "dead_handler_subjects", "retained_handler_subjects", "component_subjects", "comparison_region_subjects", "source_generation"),
        model.EquivalentSemanticRouteClaim: ("claim_id", "kind", "retired_route_subject", "replacement_route_subject", "source_subject", "destination_subjects", "route_proof_ids", "atomic_group_id", "source_generation", "dag_endpoint_subjects"),
        model.ExactInfeasibleEffectClaim: ("claim_id", "kind", "effect_subject", "source_subject", "predicate_subject", "selected_target_subject", "discarded_effect_subject", "normalized_state", "state_identity", "width", "source_write_ea", "predicate_branch_ea", "discarded_effect_ea", "selected_edge_role", "route_proof_ids", "consensus", "source_generation"),
        model.LocalAliasEffectScalarizationClaim: ("claim_id", "kind", "owner_subject", "step_index", "host_ea", "host_opcode", "alias_token", "base_token", "host_text_sha1", "value_size", "step_digest", "source_generation"),
        model.TerminalCycleBreakClaim: ("claim_id", "kind", "cycle_subject", "cleanup_source_subject", "terminal_subject", "terminal_route_proof_ids", "source_generation"),
        model.UseDefFragmentWitness: ("fragment_id", "state_identity", "redirect_owner_refs", "redirect_digest", "executed", "fragment_atomic", "actionable_non_state_severance_count", "violation_ids"),
        model.SourceBlockIdentityWitness: ("block_ref", "anchor_ea", "native_instruction_eas"),
        model.SourceIdentityCatalog: ("native_key", "generation", "blocks"),
        model.RetirementPlanMember: ("block_ref", "anchor_ea", "native_instruction_eas"),
        model.DispatcherRetirementCandidate: ("block_ref", "anchor_ea", "role", "evidence_ids", "source_generation", "candidate_id"),
        model.RetirementCandidateCatalog: ("catalog_id", "source_generation", "plan_members", "candidates"),
        model.RetirementPhaseMember: ("block_ref", "anchor_ea", "classification", "candidate_id", "candidate_reachable", "reason", "source_binding", "candidate_binding"),
        model.RetirementPhaseResult: ("result_id", "catalog_id", "claim_id", "phase", "source_fingerprint", "candidate_fingerprint", "source_generation", "candidate_generation", "members"),
        model.AuthoritativeHandlerInput: ("block_ref", "anchor_ea", "normalized_states"),
        model.UnflattenPlanInputCatalog: ("shape", "source_entry_ref", "dispatcher_entry_ref", "dispatcher_member_refs", "authoritative_handlers", "state_identity"),
        model.EntryEndpointLivenessForecast: ("reason", "normalized_state", "route_proof_id", "redirect_owner_ref", "state_write_source_ref", "state_write_instruction_ea", "dispatcher_ref", "replacement_ref", "exit_path_refs", "delivery_path_refs", "delivery_path_edges", "cut_exit_path_uses"),
        model.EntryEndpointLivenessAllowance: ("allowance_id", "reason", "normalized_state", "route_proof_id", "entry_predecessor_owner_refs", "dispatcher_old_target_ref", "replacement_endpoint_ref", "exit_path_refs", "patch_step_index", "patch_step_digest", "state_write_source_ref", "state_write_instruction_ea", "delivery_path_refs", "delivery_path_edges", "cut_exit_path_uses"),
        model.BoundEntryEndpointLivenessAllowance: ("binding_id", "allowance", "route_proof_id", "patch_step_fact", "source_fingerprint", "projected_fingerprint", "source_generation", "projected_generation", "source_inventory_digest", "projected_inventory_digest", "source_owner_successors", "projected_owner_successors", "source_liveness_safe", "projected_redirect_realized"),
        model.ProposedUnflattenContract: ("schema_version", "rule_set_version", "plan_id", "route_evidence", "source_identity_catalog", "use_def_witness", "claims", "plan_inputs", "corridor_coverage_forecast", "retirement_candidate_catalog", "entry_endpoint_liveness_allowances"),
        model.ObligationKey: ("subject", "dimension"),
        model.AuthorityJustification: ("justification_id", "rule", "premise_ids", "conclusion", "polarity", "phase", "claim_id"),
        model.ObligationEvidenceCell: ("key", "phase", "supporting_justification_ids", "refuting_justification_ids"),
        model.ObligationEvidenceIndex: ("cells",),
        model.FailedObligation: ("key", "state"),
        model.SemanticLossRow: ("case", "source_subject", "source_binding", "candidate_binding", "structural_obligation", "relevant_semantic_obligations", "justifications", "evidence", "claims"),
        model.SemanticLossLedger: ("case", "authority_id", "case_id", "phase", "source_fingerprint", "candidate_fingerprint", "rows", "ledger_id"),
        model.ObservedSemanticLossDelta: ("authority_id", "source_fingerprint", "projected_case_id", "observed_case_id", "projected_ledger_id", "observed_ledger_id", "rows", "delta_id"),
        model.PreparationBuildMetrics: ("source_inventory_builds", "candidate_inventory_builds", "inventory_ms"),
            model.SemanticPhaseMetrics: ("preparation_metrics", "source_inventory_builds", "candidate_inventory_builds", "index_folds", "view_graph_traversals", "phase", "phase_build_metrics"),
        model.PhaseBuildMetrics: ("phase", "source_inventory_builds", "candidate_inventory_builds", "inventory_ms"),
        model.InventoryPredicateObservation: ("predicate_kind", "storage_identity", "width", "compare_constant", "explicit_target_serial"),
        model.InventoryInstructionObservation: ("ordinal", "instruction_ea", "opcode", "width", "instruction_kind", "control_transfer_kind", "is_call", "call_kind", "display_text", "predicate_observation", "raw_opcode"),
        model.InventoryBlockObservation: ("serial", "block_ref", "anchor_ea", "native_instruction_eas", "predecessor_serials", "successor_serials", "transfer_ea", "instruction_observations", "block_kind", "graph_start_ea", "tail_opcode", "raw_tail_opcode", "tail_kind"),
        model.InventoryEffectSite: ("owner_serial", "owner_ref", "owner_anchor_ea", "instruction_ordinal", "instruction_ea", "effect_kind", "opcode", "width"),
        model.InventoryTerminalSite: ("owner_serial", "owner_ref", "owner_anchor_ea", "instruction_ordinal", "instruction_ea", "terminal_kind"),
        model.InventoryTopologyIncidence: ("kind", "owner_serial", "peer_serial", "source_transfer_ea"),
        model.SemanticGraphInventory: ("phase", "graph_fingerprint", "generation", "blocks", "subjects", "bindings", "effects", "terminals", "topology", "inventory_digest", "reachable_serials", "entry_serial", "source_subject_ids", "function_ea", "observed_route_topology_occurrences", "observed_lowered_conditional_topology_occurrences"),
        model.ConditionalSubjectRelation: ("source_subject_id", "target_subject_id", "dimension", "provenance_id"),
        model.PreparationAuthorityReceipt: ("receipt_id", "proposal_id", "plan_id", "source_fingerprint", "candidate_fingerprint", "source_generation", "candidate_generation", "source_inventory_digest", "candidate_inventory_digest", "source_binding_digest", "candidate_binding_digest", "route_expansion_digest", "effect_catalog_digest", "terminal_catalog_digest", "plan_input_digest", "dispatcher_member_digest", "planned_helper_digest", "patch_step_digest", "conditional_relation_digest", "projected_topology_reference_digest", "metrics", "generic_gate_facts_digest", "source_route_authority_id", "projected_route_realization_id", "corridor_coverage_forecast", "retirement_candidate_catalog"),
        model.DerivedUnflattenPreparationInputs: ("proposal", "claims", "preparation_receipt", "source_inventory", "candidate_inventory", "projected_topology_reference", "source_route_authority", "projected_route_realization", "generic_gate_facts", "conditional_relations", "patch_step_facts", "preparation_metrics", "phase_build_metrics", "corridor_coverage_phase_result", "detached_dead_handler_component_source_results", "detached_dead_handler_component_phase_results", "terminal_cycle_phase_results", "retirement_phase_result"),
        model.SemanticSafetyCase: ("case_id", "authority_id", "preparation_receipt_id", "preparation_receipt", "phase", "source_fingerprint", "candidate_fingerprint", "candidate_generation", "claims", "subjects", "bindings", "conditional_relations", "required_obligations", "evidence", "justifications", "obligation_index", "phase_metrics", "source_inventory", "candidate_inventory", "source_subject_ids", "source_bindings", "retirement_candidate_catalog", "retirement_phase_result", "corridor_coverage_phase_result", "detached_dead_handler_component_source_results", "detached_dead_handler_component_phase_results", "terminal_cycle_phase_results"),
        model.UnflattenAuthorityVerdict: ("accepted", "phase", "reason", "authority_id", "binding_id", "case_id", "candidate_fingerprint", "safety_case", "failed_obligations", "observed_acceptance", "loss_ledger", "rejection_detail"),
        model.ConditionalRoleCoordinate: ("role", "coordinate"),
        model.AnchoredBlockRef: ("ref", "anchor_ea"),
        model.EffectSiteCoordinate: ("owner", "instruction_ordinal", "instruction_ea", "effect_kind", "opcode", "width"),
        model.TerminalSiteCoordinate: ("owner", "instruction_ordinal", "instruction_ea", "terminal_kind"),
        model.RawEffectGatePhaseFact: ("phase", "source_inventory_digest", "projected_inventory_digest", "source_fingerprint", "projected_fingerprint", "source_generation", "projected_generation", "pre_effectful_source_owners", "raw_retained_source_owners", "raw_lost_source_owners", "generic_raw_payload_digest", "fact_id"),
        model.ScalarizedInstructionCoordinate: ("owner", "instruction_ordinal", "instruction_ea", "instruction_kind", "opcode", "raw_opcode", "width", "display_text_digest"),
        model.ExactEffectBindingResult: ("authority_id", "source_authority_id", "attempt_id", "phase", "claim", "proof_id", "supporting_route_relation_id", "source_subject_ids", "source_site", "source_inventory_digest", "projected_inventory_digest", "source_fingerprint", "projected_fingerprint", "source_generation", "projected_generation", "raw_effect_gate_fact_id", "binding_result_id"),
        model.LocalAliasScalarizationBindingResult: ("authority_id", "attempt_id", "phase", "claim", "source_subject_id", "source_site", "scalarized_site", "patch_step_fact", "patch_step_fact_id", "source_inventory_digest", "projected_inventory_digest", "source_fingerprint", "projected_fingerprint", "source_generation", "projected_generation", "binding_result_id"),
        model.ProjectedEffectSiteResult: ("authority_id", "attempt_id", "phase", "source_subject_id", "source_site", "outcome", "projected_subject_id", "projected_site", "scalarized_site", "lineage_kind", "relation_id", "supporting_claim_id", "supporting_binding_result_id", "latent_exact_binding_result_id", "patch_step_index", "patch_step_digest", "raw_effect_gate_fact_id", "result_id"),
        model.ProjectedTerminalSiteResult: ("authority_id", "attempt_id", "phase", "source_subject_id", "source_site", "outcome", "projected_subject_id", "projected_site", "lineage_kind", "relation_id", "result_id"),
        model.ProjectedSemanticSitePhaseResult: ("authority_id", "source_authority_id", "attempt_id", "phase", "plan_id", "source_inventory_digest", "projected_inventory_digest", "source_fingerprint", "projected_fingerprint", "source_generation", "projected_generation", "relation_ids", "raw_effect_gate_fact", "exact_effect_bindings", "local_alias_bindings", "effect_results", "terminal_results", "derived_effect_gate_fact_id", "result_id"),
        model.ProjectedRouteSitePreservation: ("authority_id", "attempt_id", "relation_id", "site_phase_result_id", "effect_result_ids", "terminal_result_ids", "preservation_id"),
        model.RouteRealizationFailure: ("claim_id", "proof_id", "route_subject_id", "scope", "proposal_id", "evidence_id", "stage", "step_index", "step_digest", "anchored_refs"),
        model.SourceBoundRouteAuthority: ("phase", "proposal", "proposal_id", "plan_id", "source_native_key", "source_fingerprint", "source_inventory_digest", "source_generation", "evidence_id", "bound_evidence", "covered_proof_ids", "covered_claim_ids", "source_authority_id"),
        model.RealizedConditionalArm: ("role", "target"),
        model.DirectRouteRealization: ("feeder", "old_target", "new_target", "relation_id"),
        model.SharedCarrierSourceBypassRouteRealization: (
            "proof_source", "shared_feeder", "comparison_entry",
            "semantic_target", "relation_id",
        ),
        model.RetainedPrefixRouteRealization: ("proof_source", "delivery_owner", "old_target", "new_target", "relation_id"),
        model.LoweredConditionalRouteRealization: ("feeder", "proof_source", "old_target", "arms", "relation_id"),
        model.ClonedConditionalRouteRealization: ("feeder", "proof_source", "old_target", "replacement_clone", "fallthrough_helper", "arms", "creation_spec_digests", "relation_id"),
        model.FoldedConditionalRouteRealization: ("feeder", "selected_target", "discarded_target", "relation_id"),
        model.ClonedSemanticInstructionOrigin: ("source_owner", "clone_owner", "source_ordinal", "projected_ordinal", "instruction_ea", "observation_digest", "origin_id"),
        model.ClonedSemanticPrefix: ("ordinal", "source_owner", "clone_owner", "source_start_ordinal", "source_end_ordinal_exclusive", "instruction_origins", "source_trailing_goto_ordinal", "projected_synthetic_goto_ordinal", "projected_successor", "creation_spec_row", "prefix_id"),
        model.TwoArmDirectBranchRouteRealization: ("feeder", "source_rewritten_arm", "projected_replacement_arm", "untouched_arm", "relation_id"),
        model.BranchFallthroughHelperRouteRealization: ("feeder", "source_fallthrough", "untouched_conditional_arm", "helper", "semantic_target", "creation_spec_digests", "relation_id"),
        model.ClonedRouteCorridorRealization: ("predecessor", "proof_source", "descriptor_old_target", "terminal_continuation", "source_corridor", "cloned_corridor", "semantic_target", "semantic_prefixes", "creation_spec_digests", "relation_id"),
        model.ClonedCarrierRouteCorridorRealization: ("proof_source", "physical_feeder", "comparison_entry", "source_corridor", "cloned_corridor", "semantic_target", "semantic_prefixes", "creation_spec_digests", "relation_id"),
        model.ProjectedRouteRealizationRow: ("claim_id", "proof_id", "route_subject_id", "relation", "site_preservation", "plan_step_index", "plan_step_type", "plan_step_digest", "source_fingerprint", "projected_fingerprint", "source_generation", "projected_generation", "row_id"),
        model.ProjectedRouteRealization: ("source_authority", "attempt_id", "plan_id", "rows", "site_phase_result", "projected_inventory_digest", "projected_fingerprint", "projected_generation", "realization_id"),
        model.SourceBoundRouteAuthorityAccepted: ("authority",),
        model.SourceBoundRouteAuthorityRejected: ("failures",),
        model.ProjectedRouteRealizationAccepted: ("realization",),
        model.ProjectedRouteRealizationRejected: ("failures",),
    })
    _EXTERNAL_TYPES.update({
        NativePreanalysisKey, NativeEaInterval, NativeEaIntervalSet, StorageIdentity,
        InstructionEffectSite,
        StableBlockIdentity, LogicalBlockRef, NativeBlockRef, PlanBlockRef,
        TransactionAttemptId,
                    route.SemanticCorridorPoint, route.SemanticLogicalDagEndpoint,
                    route.SemanticRecoveredStateWriteWitness,
                    route.SemanticPhysicalGuardSelectionWitness,
                    route.SemanticPhysicalStateWriteWitness,
                    route.SemanticGuardedStateSelection,
                    route.SemanticPhysicalDeliveryMember,
                    route.SemanticPhysicalDeliveryProof,
                route.SemanticPredicateProof, route.SemanticCarrierProof,
                route.SemanticRouteDestination, route.SemanticStateWriteProof,
                route.SemanticTerminalDeliveryProof, route.SemanticReturnValueTransportProof,
                route.SemanticRouteProof,
                        route.SemanticBootstrapProof,
                        route.SemanticStateTransformProof, route.SemanticStateCarrierProof,
                        route.SemanticDecisionDagWitness, route.SemanticDagComparison,
                        route.SemanticSwitchTableHandoff,
                        route.SemanticDagNamespaceBridge,
                        route.SemanticStateDagProof, route.SemanticPartitionMemberProof,
                        route.SemanticPartitionConditionalEdgeProof,
                        route.SemanticStatePartitionProof,
                    route.BoundSemanticStateTransform, route.BoundSemanticStateCarrier,
                    route.BoundSemanticStateDag, route.BoundSemanticStatePartition,
                    route.BoundSemanticBootstrap,
            route.CanonicalSemanticEvidence,
            route.BoundSemanticBlock, route.BoundSemanticRouteDestination,
            route.BoundSemanticPredicate, route.BoundSemanticCarrier,
            route.BoundSemanticRoute, route.BoundCanonicalSemanticEvidence,
        TerminalReturnCarrierEvidence,
        gates.GenericEntryGateFacts, gates.GenericEffectfulGateFacts,
        gates.GenericTerminalGateFacts, gates.GenericCfgGateFacts,
        TerminalReturnCarrierSource, TerminalReturnCarrierRequest,
        PreserveLivePredicateCondition, SyntheticCounterBoundCondition,
        SyntheticRegisterNonzeroCondition,
        SyntheticStackValueEqualsCondition,
        PatchBlockSpec, PatchEdgeRef,
        Varnode, Instruction, InstructionControl, InstructionEffect,
        InstructionMemoryAccess, InstructionSwitchCase,
        Add, And, Const, Load, Move, Mul, Store, Sub,
        DefinitionRef, InstructionResultRef, SSAValueRef, TemporaryRef,
        AggregateLocation, MemoryCell, RegisterLocation, StackSlot, WeakStackSlot,
    })
    _EXTERNAL_FIELDS.update({
        NativePreanalysisKey: ("schema_version", "input_identity", "processor", "bitness", "function_rva", "function_fingerprint", "profile_fingerprint", "sdk_fingerprint"),
        TransactionAttemptId: ("plan_id", "session_id", "generation", "attempt_id"),
        NativeEaInterval: ("start_ea", "end_ea"),
        NativeEaIntervalSet: ("intervals",),
        StorageIdentity: ("kind", "offset"),
        InstructionEffectSite: ("instruction_ea", "kind", "host_instruction_ea"),
        Varnode: ("space", "offset", "size"),
        InstructionSwitchCase: ("values", "target"),
        InstructionControl: ("transfer", "predicate", "target", "fallthrough", "switch_cases", "indirect_target", "call_kind", "call_target", "call_args", "return_value"),
        InstructionEffect: ("kind", "target", "segment", "value", "args"),
        InstructionMemoryAccess: ("kind", "target", "segment", "value", "width"),
        Instruction: ("operation", "inputs", "result", "effects", "control", "memory", "attrs", "input_exprs", "operand_expr_fragments"),
        Const: ("value",), Move: ("source",), Add: ("left", "right"),
        And: ("left", "right"), Load: ("address",), Mul: ("left", "right"),
        Store: ("address", "value"), Sub: ("left", "right"),
        DefinitionRef: ("location", "version"), InstructionResultRef: ("insn", "result_index"),
        SSAValueRef: ("value_id",), TemporaryRef: ("temp_id",),
        StackSlot: ("offset", "size"), RegisterLocation: ("register_id", "size"),
        MemoryCell: ("address", "size"), WeakStackSlot: ("size",),
        AggregateLocation: ("members",),
        StableBlockIdentity: ("native_key", "exact_instruction_eas", "native_ranges"),
        LogicalBlockRef: ("session_id", "proxy_token", "version"),
        NativeBlockRef: ("identity",),
        PlanBlockRef: ("plan_id", "local_block_id"),
        route.SemanticCorridorPoint: ("identity", "anchor_ea"),
        route.SemanticLogicalDagEndpoint: ("kind", "serial", "session_id", "proxy_token", "version"),
        route.SemanticPhysicalGuardSelectionWitness: (
            "guard_serial", "comparison_instruction", "state_identity", "width",
            "constant", "true_target_serial", "false_target_serial",
            "selected_target_serial",
        ),
        route.SemanticGuardedStateSelection: (
            "guard", "comparison_instruction", "state_identity", "width",
            "constant", "true_target", "false_target", "selected_target",
        ),
        route.SemanticPredicateProof: ("kind", "origin", "consumer", "corridor", "storage_identity", "width", "compare_constant", "true_is_taken", "permitted_write_eas"),
        route.SemanticCarrierProof: ("carrier_id", "definition", "consumers", "corridor", "storage_identity", "width", "state_values", "permitted_write_eas"),
        route.SemanticRouteDestination: ("role", "state_constant", "target_identity", "target_anchor_ea", "terminal"),
                route.SemanticRecoveredStateWriteWitness: ("source_instruction", "state_identity", "width", "recovered_state"),
                route.SemanticPhysicalStateWriteWitness: (
                    "source_instruction",
                    "state_identity",
                    "width",
                    "state_constant",
                    "source_serial",
                    "alias_definition_instruction",
                    "alias_definition_serial",
                    "physical_width",
                    "state_lane_offset",
                    "byte_order",
                    "guarded_selection",
                ),
                route.SemanticPhysicalDeliveryMember: (
                    "identity", "instruction_ea", "physical_state_write",
                    "alias_definition",
                ),
                route.SemanticPhysicalDeliveryProof: (
                    "delivery", "delivery_instruction", "target", "members",
                ),
                route.SemanticStateWriteProof: ("identity", "instruction_ea", "state_variable", "width", "state_constant", "corridor_instruction_eas", "authority_transfer_ea", "preserved_call_instruction_eas", "delivery_kind", "recovered_state_write", "physical_state_write", "physical_delivery", "guarded_selection"),
                route.SemanticReturnValueTransportProof: ("exit_entry", "move_instruction", "move_source_identity", "move_source_width", "move_destination_identity", "move_destination_width", "carrier", "carrier_instruction", "carrier_source_identity", "carrier_source_width", "carrier_result_width", "logical_exit"),
                route.SemanticTerminalDeliveryProof: ("state_write_instruction", "state_identity", "width", "state_constant", "outer_state_dag", "exit_entry", "return_transport"),
                route.SemanticStateTransformProof: ("operation", "program", "source_bindings", "owner_identity", "owner_anchor_ea", "source_identity", "source_anchor_ea", "feeder_identity", "feeder_anchor_ea", "comparison_entry_identity", "comparison_entry_anchor_ea", "state_feeder_identity", "state_feeder_anchor_ea", "state_identity", "state_constant", "corridor", "corridor_instruction_eas"),
                    route.SemanticStateCarrierProof: ("carrier", "owner_identity", "owner_anchor_ea", "source_identity", "source_anchor_ea", "feeder_identity", "feeder_anchor_ea", "comparison_entry_identity", "comparison_entry_anchor_ea", "state_identity", "state_constant", "requires_feeder_clone", "corridor"),
                        route.SemanticDagComparison: ("node", "operation", "constant", "true_target", "false_target", "state_identity"),
                        route.SemanticDagNamespaceBridge: ("node", "instruction_ea", "source_identity", "result_identity", "source_width", "result_width"),
                        route.SemanticDecisionDagWitness: ("state_identity", "state_constant", "entry", "path", "comparisons", "aliases", "bridges"),
                            route.SemanticPartitionConditionalEdgeProof: ("transfer_instruction_ea", "transfer_instruction", "edge_role", "sibling_identity", "sibling_anchor_ea"),
                            route.SemanticPartitionMemberProof: ("owner_identity", "owner_anchor_ea", "state_constant", "conditional_edge"),
                        route.SemanticStatePartitionProof: ("group_id", "feeder_identity", "feeder_anchor_ea", "feeder_instruction_ea", "state_identity", "members"),
                        route.SemanticStatePartitionSwitchTableProof: ("dispatcher_identity", "dispatcher_anchor_ea", "target_identity", "target_anchor_ea", "state_identity", "state_constant"),
                        route.SemanticSwitchTableHandoff: ("dispatcher", "state_identity", "state_constant"),
                        route.SemanticStateDagProof: ("witness", "source_identity", "source_anchor_ea", "target_identity", "target_anchor_ea", "entry_identity", "entry_anchor_ea", "source_to_entry_corridor", "path", "switch_handoff"),
                        route.SemanticBootstrapProof: ("entry", "source", "owner", "dispatcher", "corridor", "state_write", "state_dag", "preserved_effect_sites"),
        route.SemanticRouteProof: ("proof_id", "atomic_group_id", "proof_kind", "shape", "source_identity", "source_anchor_ea", "destinations", "delivery_region", "source_owner_identity", "source_owner_anchor_ea", "state_write", "state_transform", "state_carrier", "state_partition", "state_partition_switch_table", "state_dag", "bootstrap", "predicate", "carriers", "terminal_return_carrier", "terminal_delivery", "diagnostic_provenance"),
            route.CanonicalSemanticEvidence: ("native_key", "generation", "atomic_group_id", "route_proofs"),
            route.BoundSemanticBlock: ("serial", "identity", "anchor_ea"),
            route.BoundSemanticRouteDestination: ("evidence", "block"),
            route.BoundSemanticPredicate: ("evidence", "origin", "consumer", "corridor"),
                route.BoundSemanticCarrier: ("evidence", "definition", "consumers", "corridor"),
                    route.BoundSemanticStateTransform: ("evidence", "owner", "source", "feeder", "comparison_entry", "state_feeder"),
                        route.BoundSemanticStateCarrier: ("evidence", "owner", "source", "feeder", "comparison_entry"),
                            route.BoundSemanticStateDag: ("evidence", "source", "target", "entry", "source_to_entry_corridor", "path", "switch_handoff_dispatcher"),
                        route.BoundSemanticStatePartition: ("evidence", "feeder", "owners"),
                        route.BoundSemanticStatePartitionSwitchTable: ("evidence", "dispatcher", "target"),
                        route.BoundSemanticBootstrap: ("evidence", "entry", "source", "owner", "dispatcher", "corridor"),
                        route.BoundSemanticRoute: ("evidence", "source", "destinations", "source_owner", "state_write_block", "state_transform", "state_carrier", "state_partition", "state_partition_switch_table", "state_dag", "bootstrap", "predicate", "carriers"),
            route.BoundCanonicalSemanticEvidence: ("evidence", "routes"),
        gates.GenericEntryGateFacts: ("passed", "pre_reachable_count", "post_reachable_count", "retained_ratio", "min_pre_reachable", "min_retained_ratio", "reason"),
        gates.GenericEffectfulGateFacts: ("passed", "pre_effectful_block_serials", "post_reachable_effectful_block_serials", "lost_block_serials", "reason"),
        gates.GenericTerminalGateFacts: ("passed", "pre_reachable_terminals", "post_reachable_terminals", "pre_reachable_count", "post_reachable_count", "reason"),
        gates.GenericCfgGateFacts: ("entry", "effectful_raw", "effectful_effective", "terminal"),
        TerminalReturnCarrierEvidence: ("request", "capture_identity", "terminal_identity", "state_write_ea", "carrier_ea", "terminal_return_ea", "operation", "source", "return_width", "corridor_instruction_eas"),
        TerminalReturnCarrierSource: ("kind", "width", "storage_identity", "constant"),
        TerminalReturnCarrierRequest: ("source_handler_ea", "terminal_target_ea", "state_var_reg", "state_constant"),
        PreserveLivePredicateCondition: ("predicate_ea", "true_is_taken", "preserve_live_predicate"),
        SyntheticCounterBoundCondition: (
            "counter_size", "bound", "counter_stkoff", "counter_reg", "signed",
        ),
        SyntheticRegisterNonzeroCondition: ("predicate_reg", "predicate_size"),
        SyntheticStackValueEqualsCondition: ("stack_stkoff", "stack_size", "value"),
        PatchEdgeRef: ("source", "target"),
        PatchBlockSpec: ("block_id", "kind", "template_block", "incoming_edge", "outgoing_edges", "instructions", "captured_body"),
    })
    for enum_type in _ENUM_TYPES:
        if enum_type.__name__ in _ENUM_BY_NAME and _ENUM_BY_NAME[enum_type.__name__] is not enum_type:
            raise RuntimeError(f"duplicate canonical enum name: {enum_type.__name__}")
        _ENUM_BY_NAME[enum_type.__name__] = enum_type
    for record_type in (*_RECORD_TYPES, *_EXTERNAL_TYPES):
        if record_type.__name__ in _RECORD_BY_NAME and _RECORD_BY_NAME[record_type.__name__] is not record_type:
            raise RuntimeError(f"duplicate canonical record name: {record_type.__name__}")
        _RECORD_BY_NAME[record_type.__name__] = record_type
    for record_type, names in _RECORD_FIELDS.items():
        declared = tuple(field.name for field in fields(record_type) if not field.name.startswith("_"))
        if names != declared:
            raise RuntimeError(f"canonical record schema drift: {record_type.__name__}")
    for external_type, names in _EXTERNAL_FIELDS.items():
        declared = tuple(field.name for field in fields(external_type) if not field.name.startswith("_"))
        if external_type is NativePreanalysisKey:
            expected = ("schema_version",) + declared
        else:
            expected = declared
        if names != expected:
            raise RuntimeError(f"canonical external schema drift: {external_type.__name__}")
    _REGISTRIES_READY = True


def _wire(value: object) -> object:
    _ensure_registries()
    if value is None:
        return {"t": "none"}
    if type(value) is bool:
        return {"t": "bool", "v": value}
    if type(value) is int:
        return {"t": "int", "v": str(value)}
    if type(value) is str:
        return {"t": "str", "v": value}
    if type(value) is bytes:
        return {"t": "bytes", "v": value.hex()}
    if isinstance(value, Enum):
        if type(value) not in _ENUM_TYPES:
            raise TypeError(f"unregistered enum type: {type(value).__name__}")
        return {"t": "enum", "n": type(value).__name__, "v": _wire(value.value)}
    if type(value) is dict or type(value) is MappingProxyType:
        mapping = _exact_canonical_mapping(value)
        if any(type(key) is not str for key in dict.__iter__(mapping)):
            raise TypeError("canonical mappings require string keys")
        pairs = [(_wire(key), _wire(item)) for key, item in dict.items(mapping)]
        pairs.sort(key=lambda pair: _json_bytes(pair[0]))
        return {"t": "map", "v": [[key, item] for key, item in pairs]}
    if isinstance(value, Mapping):
        raise TypeError("canonical mappings require an exact dict or mappingproxy")
    if type(value) is list:
        return {"t": "list", "v": [_wire(item) for item in value]}
    if type(value) is tuple:
        return {"t": "tuple", "v": [_wire(item) for item in value]}
    if type(value) is frozenset:
        items = [_wire(item) for item in value]
        items.sort(key=_json_bytes)
        return {"t": "frozenset", "v": items}
    if type(value) in _PINNED_RECORD_TYPES:
        _validate_pinned_record(value)
    if type(value) in _EXTERNAL_TYPES:
        return _external_wire(value)
    if type(value) in _RECORD_TYPES and is_dataclass(value):
        names = _RECORD_FIELDS[type(value)]
        pairs = []
        for name in names:
            field_value = getattr(value, name)
            if type(value).__name__ in {"PreparationBuildMetrics", "PhaseBuildMetrics"} and name == "inventory_ms":
                if type(field_value) not in (int, float) or not math.isfinite(float(field_value)):
                    raise ValueError("invalid preparation metric")
                encoded = {"t": "decimal", "v": float(field_value).hex()}
            else:
                encoded = _wire(field_value)
            pairs.append([name, encoded])
        return {"t": "record", "n": type(value).__name__, "v": pairs}
    raise TypeError(f"no canonical encoding for {type(value).__name__}")


def _external_wire(value: object) -> object:
    names = _EXTERNAL_FIELDS.get(type(value))
    if names is None:
        raise TypeError(f"unregistered external type: {type(value).__name__}")
    pairs = []
    for name in names:
        item = type(value).SCHEMA_VERSION if type(value).__name__ == "NativePreanalysisKey" and name == "schema_version" else getattr(value, name)
        if type(value).__name__ == "GenericEntryGateFacts" and name in {"retained_ratio", "min_retained_ratio"}:
            if type(item) is not float or not math.isfinite(item):
                raise ValueError("invalid generic gate ratio")
            encoded = {"t": "decimal", "v": item.hex()}
        else:
            encoded = _wire(item)
        pairs.append([name, encoded])
    return {"t": "record", "n": type(value).__name__, "v": pairs}


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


class OccurrenceDigest(bytes):
    """A phase-local cache *guard*, never an authority or content digest.

    It is deliberately not interchangeable with the ``sha256:`` content IDs
    this module mints.  An ``OccurrenceDigest`` covers ``id()`` values for
    cycles and for values of unregistered types, so it is reproducible only
    within one process and only while those objects are alive.  It answers
    exactly one question -- "is this same object still byte-identical to when
    it was cached" -- and must never be persisted, compared across processes,
    or used as a cache key.

    Subclassing ``bytes`` keeps equality, hashing and the session caches
    working unchanged while giving the value a name that cannot be mistaken
    for an authority digest at a call site.
    """

    __slots__ = ()

    def __repr__(self) -> str:
        return f"OccurrenceDigest({bytes(self).hex()})"


class _OccurrenceHasher(Protocol):
    """The only hasher capability the occurrence walk uses."""

    def update(self, data: bytes, /) -> None: ...

    def digest(self) -> bytes: ...


#: Exact type object -> its stamp token.  Unbounded by design and safe: the
#: table can only ever hold the distinct types the authority canonicalizes in
#: this process (they are module-level singletons, so the set is finite and
#: small), and the strong reference is load-bearing -- it is what stops a
#: dead type's ``id()`` from being recycled by a later type and silently
#: aliasing two stamps.  Evicting an entry would trade bounded memory for an
#: unsound guard.
_OCCURRENCE_TYPE_TOKENS: dict[type, bytes] = {}


def _occurrence_type_token(cls: type) -> bytes:
    """Return one process-stable token standing for an exact type object.

    The tuple mirror this replaced compared types by identity (tuple equality
    falls back to ``is`` for type objects). The token embeds ``id(cls)`` and
    ``_OCCURRENCE_TYPE_TOKENS`` holds a strong reference, so no live type can
    be confused with a later type that reuses its address.
    """

    token = _OCCURRENCE_TYPE_TOKENS.get(cls)
    if token is None:
        token = f"{id(cls)}:{cls.__module__}.{cls.__qualname__}".encode(
            "utf-8", "surrogatepass"
        )
        _OCCURRENCE_TYPE_TOKENS[cls] = token
    return token


def _feed_occurrence_token(
    hasher: _OccurrenceHasher, tag: bytes, payload: bytes
) -> None:
    """Append one length-delimited token so no two shapes can alias."""

    hasher.update(tag)
    hasher.update(len(payload).to_bytes(8, "little"))
    hasher.update(payload)


def _feed_occurrence(
    value: object, hasher: _OccurrenceHasher, seen: set[int]
) -> None:
    """Stream one value's structural shape into ``hasher``."""

    if value is None or type(value) in (bool, int, str, bytes):
        _feed_occurrence_token(hasher, b"a", _occurrence_type_token(type(value)))
        if value is None:
            payload = b""
        elif type(value) is bytes:
            payload = value
        elif type(value) is str:
            payload = value.encode("utf-8", "surrogatepass")
        else:
            payload = repr(value).encode("ascii")
        _feed_occurrence_token(hasher, b"v", payload)
        return
    if type(value) is float:
        _feed_occurrence_token(hasher, b"f", value.hex().encode("ascii"))
        return
    if isinstance(value, Enum):
        _feed_occurrence_token(hasher, b"e", _occurrence_type_token(type(value)))
        _feed_occurrence_token(
            hasher, b"v", value.name.encode("utf-8", "surrogatepass")
        )
        return
    marker = id(value)
    if type(value) is dict or type(value) is MappingProxyType:
        if marker in seen:
            _feed_occurrence_token(hasher, b"c", repr(marker).encode("ascii"))
            return
        seen.add(marker)
        try:
            mapping = _exact_canonical_mapping(value)
            _feed_occurrence_token(hasher, b"m", _occurrence_type_token(type(value)))
            hasher.update(len(mapping).to_bytes(8, "little"))
            for key, item in dict.items(mapping):
                _feed_occurrence(key, hasher, seen)
                _feed_occurrence(item, hasher, seen)
        finally:
            seen.remove(marker)
        return
    if type(value) in (list, tuple, frozenset):
        if marker in seen:
            _feed_occurrence_token(hasher, b"c", repr(marker).encode("ascii"))
            return
        seen.add(marker)
        try:
            _feed_occurrence_token(hasher, b"s", _occurrence_type_token(type(value)))
            hasher.update(len(value).to_bytes(8, "little"))
            for item in value:
                _feed_occurrence(item, hasher, seen)
        finally:
            seen.remove(marker)
        return
    _ensure_registries()
    names = _RECORD_FIELDS.get(type(value), _EXTERNAL_FIELDS.get(type(value)))
    if names is not None:
        if marker in seen:
            _feed_occurrence_token(hasher, b"c", repr(marker).encode("ascii"))
            return
        seen.add(marker)
        try:
            _feed_occurrence_token(hasher, b"r", _occurrence_type_token(type(value)))
            hasher.update(len(names).to_bytes(8, "little"))
            native_key = type(value).__name__ == "NativePreanalysisKey"
            for name in names:
                _feed_occurrence_token(
                    hasher, b"n", name.encode("utf-8", "surrogatepass")
                )
                _feed_occurrence(
                    type(value).SCHEMA_VERSION
                    if native_key and name == "schema_version"
                    else getattr(value, name),
                    hasher,
                    seen,
                )
        finally:
            seen.remove(marker)
        return
    _feed_occurrence_token(hasher, b"u", _occurrence_type_token(type(value)))
    _feed_occurrence_token(hasher, b"i", repr(marker).encode("ascii"))


def _occurrence_stamp(value: object) -> OccurrenceDigest:
    """Return a fixed-size structural digest guarding one cache entry.

    This is an entry guard, never a cache key or an authority digest.  It
    avoids dataclass equality and recursive hashing while detecting an
    ``object.__setattr__`` mutation before a phase-local cached byte string or
    record ID can be returned for the wrong live content.

    The stamp is a digest rather than the recursive tuple mirror it started
    as.  The mirror measured ~2.3x the deep size of the value it guarded and
    stayed alive in ``canonical_bytes`` across ``_wire`` and ``json.dumps``,
    while the session retained one mirror per cached record -- O(nodes x
    depth) for nested records, 21.7x the value's own size at depth 9.  On
    Target A that exhausted the heap and ``json.dumps`` raised ``MemoryError``
    inside the preflight (ticket d81-aw7v).  A digest answers the only
    question a guard asks -- "is this exact object still byte-identical?" --
    in constant space.
    """

    # One attribution per root stamp.  Every call to this function is a
    # root: the recursion lives in ``_feed_occurrence``, which must never
    # record, or the per-lookup counters would count nodes, not walks.
    record_occurrence_stamp()
    hasher = hashlib.blake2b(digest_size=32)
    _feed_occurrence(value, hasher, set())
    return OccurrenceDigest(hasher.digest())


_SEALED_ATOM_TYPES = (int, str, bytes)


class _SealedGuard:
    """Identity guard over one occurrence's direct children (trusted mode).

    Holds strong references to the children so their ``id()`` values cannot be
    recycled while the entry lives.  Two guards are equal when every child is
    the same object, an equal atom of the same exact type, or (for a replaced
    child only) a structurally equal occurrence per :func:`_occurrence_stamp`.
    Never an authority digest, never a cache key.
    """

    __slots__ = ("children",)

    def __init__(self, children: tuple[object, ...]) -> None:
        self.children = children

    def __eq__(self, other: object) -> bool:
        if type(other) is not _SealedGuard:
            return NotImplemented
        mine = self.children
        theirs = other.children
        if len(mine) != len(theirs):
            return False
        for item, live in zip(mine, theirs):
            if item is live:
                continue
            item_type = type(item)
            if item_type is not type(live):
                return False
            if item_type in _SEALED_ATOM_TYPES:
                if item == live:
                    continue
                return False
            if _occurrence_stamp(item) != _occurrence_stamp(live):
                return False
        return True

    __hash__ = None


def _sealed_guard(value: object) -> _SealedGuard:
    """Return the direct-children guard for one occurrence (no recursion)."""

    if value is None or type(value) in (bool, int, str, bytes, float):
        return _SealedGuard((value,))
    if isinstance(value, Enum):
        return _SealedGuard((value,))
    if type(value) is dict or type(value) is MappingProxyType:
        mapping = _exact_canonical_mapping(value)
        children: list[object] = []
        for key, item in dict.items(mapping):
            children.append(key)
            children.append(item)
        return _SealedGuard(tuple(children))
    if type(value) in (list, tuple, frozenset):
        return _SealedGuard(tuple(value))
    _ensure_registries()
    names = _RECORD_FIELDS.get(type(value), _EXTERNAL_FIELDS.get(type(value)))
    if names is not None:
        if type(value).__name__ == "NativePreanalysisKey":
            return _SealedGuard(tuple(
                type(value).SCHEMA_VERSION if name == "schema_version"
                else getattr(value, name)
                for name in names
            ))
        return _SealedGuard(tuple(getattr(value, name) for name in names))
    return _SealedGuard((("unknown", type(value), id(value)),))


def _occurrence_guard(session: object, value: object) -> object:
    """Return the cache-entry guard the active session's mode requires."""

    if session.trust_sealed:
        return _sealed_guard(value)
    return _occurrence_stamp(value)


def canonical_bytes(
    value: object, *, _record_lookup: object = record_bytes_lookup,
) -> bytes:
    """Encode ``value``; ``_record_lookup`` attributes the session lookup path.

    Content-ID callers pass their own attribution but still enter through this
    public function, so a module-attribute wrapper observes every root encode.
    """

    session = active_canonical_session()
    stamp = None if session is None else _occurrence_guard(session, value)
    if session is not None:
        cached = session.cached_canonical_bytes(value, stamp)
        _record_lookup(cached is not None)
        if cached is not None:
            record_canonical_bytes_reuse()
            return cached
    _validate_canonical_value(value)
    record_deep_validation()
    wire = _wire(value)
    record_wire_encode()
    data = _json_bytes(wire)
    if session is not None:
        session.store_canonical_bytes(value, stamp, data)
    return data


def _decode_wire(value: object, *, allow_index: bool = False) -> object:
    _ensure_registries()
    if not isinstance(value, dict) or not isinstance(value.get("t"), str):
        raise ValueError("invalid canonical wire value")
    tag = value["t"]
    expected = {
        "none": {"t"}, "bool": {"t", "v"}, "int": {"t", "v"},
        "str": {"t", "v"}, "decimal": {"t", "v"}, "bytes": {"t", "v"}, "list": {"t", "v"},
        "tuple": {"t", "v"}, "frozenset": {"t", "v"}, "map": {"t", "v"},
        "enum": {"t", "n", "v"}, "record": {"t", "n", "v"},
    }.get(tag)
    if expected is None or set(value) != expected:
        raise ValueError("invalid canonical wire tag shape")
    if tag == "none":
        result: object = None
    elif tag == "bool":
        if type(value["v"]) is not bool:
            raise ValueError("invalid bool wire value")
        result = value["v"]
    elif tag == "int":
        if type(value["v"]) is not str or not value["v"] or (value["v"] != "0" and value["v"].startswith("0")):
            raise ValueError("invalid int wire value")
        try:
            result = int(value["v"])
        except ValueError as exc:
            raise ValueError("invalid int wire value") from exc
    elif tag == "str":
        if type(value["v"]) is not str:
            raise ValueError("invalid str wire value")
        result = value["v"]
    elif tag == "decimal":
        if type(value["v"]) is not str:
            raise ValueError("invalid decimal wire value")
        try:
            result = float.fromhex(value["v"])
        except ValueError as exc:
            raise ValueError("invalid decimal wire value") from exc
        if not math.isfinite(result):
            raise ValueError("invalid decimal wire value")
    elif tag == "bytes":
        if type(value["v"]) is not str:
            raise ValueError("invalid bytes wire value")
        try:
            result = bytes.fromhex(value["v"])
        except ValueError as exc:
            raise ValueError("invalid bytes wire value") from exc
    elif tag == "list":
        if type(value["v"]) is not list:
            raise ValueError("invalid list wire value")
        result = [_decode_wire(item, allow_index=allow_index) for item in value["v"]]
    elif tag == "tuple":
        if type(value["v"]) is not list:
            raise ValueError("invalid tuple wire value")
        result = tuple(_decode_wire(item, allow_index=allow_index) for item in value["v"])
    elif tag == "frozenset":
        if type(value["v"]) is not list:
            raise ValueError("invalid frozenset wire value")
        result = frozenset(_decode_wire(item, allow_index=allow_index) for item in value["v"])
    elif tag == "map":
        if type(value["v"]) is not list:
            raise ValueError("invalid map wire value")
        result = {}
        for encoded_key, item in value["v"]:
            if type(encoded_key) is not dict or type(item) is not dict:
                raise ValueError("invalid map pair")
            key = _decode_wire(encoded_key, allow_index=allow_index)
            if type(key) is not str:
                raise ValueError("canonical mapping key must decode to string")
            if key in result:
                raise ValueError("duplicate canonical mapping key")
            result[key] = _decode_wire(item, allow_index=allow_index)
    elif tag == "enum":
        if type(value["n"]) is not str:
            raise ValueError("invalid enum name")
        enum_type = _ENUM_BY_NAME.get(value["n"])
        if enum_type is None:
            raise ValueError("unknown enum name")
        raw = _decode_wire(value["v"], allow_index=allow_index)
        try:
            result = enum_type(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError("unknown enum value") from exc
    else:
        if type(value["n"]) is not str or type(value["v"]) is not list:
            raise ValueError("invalid record wire value")
        record_type = _RECORD_BY_NAME.get(value["n"])
        if record_type is None:
            raise ValueError("unknown record name")
        names = _RECORD_FIELDS.get(record_type, _EXTERNAL_FIELDS.get(record_type))
        if names is None or len(value["v"]) != len(names):
            raise ValueError("invalid record fields")
        seen: set[str] = set()
        kwargs: dict[str, object] = {}
        for pair, expected_name in zip(value["v"], names):
            if type(pair) is not list or len(pair) != 2 or type(pair[0]) is not str:
                raise ValueError("invalid record field")
            name = pair[0]
            if name in seen or name != expected_name:
                raise ValueError("invalid record field order")
            seen.add(name)
            kwargs[name] = _decode_wire(
                pair[1],
                allow_index=(allow_index or (
                    record_type.__name__ == "SemanticSafetyCase"
                    and name == "obligation_index"
                )),
            )
        try:
            if record_type.__name__ == "NativePreanalysisKey":
                result = record_type.from_dict(kwargs)
            elif record_type.__name__ == "ObligationEvidenceIndex":
                if not allow_index:
                    raise ValueError("obligation indexes require case context")
                # Keep untrusted serialized cells unprivileged until the
                # surrounding case has recomputed and compared its fold.
                result = _DecodedIndexCells(kwargs["cells"])
            elif record_type.__name__ == "PreparationAuthorityReceipt":
                # Receipts are constructor-closed transaction records, but
                # canonical replay must still reconstruct and revalidate
                # the exact sealed value carried by a safety case.
                result = record_type.__new__(record_type)
                for name, item in kwargs.items():
                    object.__setattr__(result, name, item)
                object.__setattr__(result, "_minted", True)
                record_type.__post_init__(result)
            elif record_type.__name__ == "SourceBoundRouteAuthority":
                # Re-enter the binder's closed minting kernel so replay keeps
                # the source-authority seal and registry contract intact.
                from d810.transforms.unflatten_authority.bind import bind_source_route_authority

                mint = next(
                    (
                        cell.cell_contents
                        for cell in (bind_source_route_authority.__closure__ or ())
                        if getattr(cell.cell_contents, "__name__", None) == "_route_mint"
                    ),
                    None,
                )
                if mint is None:
                    raise ValueError("source authority minting kernel is unavailable")
                result = mint(record_type, kwargs, "source_authority_id")
            elif record_type.__name__ in {
                "EffectSiteCoordinate", "TerminalSiteCoordinate", "RawEffectGatePhaseFact",
                "ScalarizedInstructionCoordinate", "ExactEffectBindingResult",
                "LocalAliasScalarizationBindingResult", "ProjectedEffectSiteResult",
                "ProjectedTerminalSiteResult", "ProjectedSemanticSitePhaseResult",
                "ProjectedRouteSitePreservation",
            }:
                raise ValueError("semantic site authority records are encode-only")
            elif record_type.__name__ in {
                "RouteRealizationFailure",
                "ObservedRouteTopologyOccurrence",
                "ObservedLoweredConditionalTopologyOccurrence",
                "DirectRouteRealization", "SharedCarrierSourceBypassRouteRealization",
                "RetainedPrefixRouteRealization",
                "LoweredConditionalRouteRealization", "ClonedConditionalRouteRealization",
                "FoldedConditionalRouteRealization",
                "ClonedSemanticInstructionOrigin", "ClonedSemanticPrefix",
                "TwoArmDirectBranchRouteRealization", "BranchFallthroughHelperRouteRealization",
                "ClonedRouteCorridorRealization", "ClonedCarrierRouteCorridorRealization",
                "ProjectedRouteRealizationRow", "ProjectedRouteRealization",
            }:
                raise ValueError("route realization authority records are encode-only")
            elif record_type.__name__ == "SemanticSafetyCase":
                serialized_index = kwargs.get("obligation_index")
                if not isinstance(serialized_index, _DecodedIndexCells):
                    raise ValueError("case obligation index lacks decode context")
                from d810.transforms.unflatten_authority.evaluate import (
                    _build_obligation_index,
                    _validate_justification_graph,
                )
                _validate_justification_graph(
                    kwargs["justifications"], kwargs["required_obligations"],
                    kwargs["evidence"], kwargs["phase"], kwargs["claims"],
                    kwargs["conditional_relations"],
                    candidate_fingerprint=kwargs["candidate_fingerprint"],
                    candidate_generation=kwargs["candidate_generation"],
                    bindings=kwargs["bindings"],
                    subjects=kwargs["subjects"],
                    source_subject_ids=kwargs["source_subject_ids"],
                )
                expected_index = _build_obligation_index(
                    kwargs["required_obligations"], kwargs["justifications"], kwargs["phase"],
                )
                if serialized_index.cells != expected_index.cells:
                    raise ValueError("serialized obligation index does not match the case fold")
                kwargs["obligation_index"] = expected_index
                result = record_type(**kwargs)
            else:
                result = record_type(**kwargs)
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid record value") from exc
        if type(result) in _PINNED_RECORD_TYPES:
            _validate_pinned_record(result)
    if isinstance(result, _DecodedIndexCells):
        return result
    if tag == "decimal":
        canonical_value = {"t": "decimal", "v": result.hex()}
    else:
        canonical_value = _wire(result)
    if canonical_value != value:
        raise ValueError("non-canonical wire encoding")
    return result


def canonical_decode(encoded: bytes) -> object:
    if not isinstance(encoded, bytes):
        raise TypeError("canonical encoding must be bytes")
    try:
        value = json.loads(encoded.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid canonical encoding") from exc
    result = _decode_wire(value)
    if type(result).__name__ == "ObligationEvidenceIndex":
        raise ValueError("obligation indexes are evaluator-owned and require case context")
    if canonical_bytes(result) != encoded:
        raise ValueError("non-canonical canonical encoding")
    record_roundtrip_decode()
    return result


def validate_canonical_roundtrip(value: object, expected_type: type[object]) -> object:
    """Require the exact persistence decode and canonical representation."""

    encoded = canonical_bytes(value)
    decoded = canonical_decode(encoded)
    if type(decoded) is not expected_type or decoded != value:
        raise ValueError("canonical roundtrip changed the authority value")
    return decoded


def validate_live_semantic_fields(
    value: object, expected_type: type[object],
) -> None:
    """Validate one *live* record's semantic fields without canonicalising it.

    This is the live-construction half of the dual identity: it proves the
    record's exact type and that every value reachable from it is an exact,
    registered, canonically representable value -- the same walk
    ``canonical_bytes`` performs before it encodes -- and it stops there.  No
    wire tree is built, no JSON is produced, no SHA-256 is computed and no
    decode is attempted, so a record that never leaves the process never pays
    for a representation nobody reads.

    The canonical representation of the same record is built by
    :func:`materialize_for_persistence` at an explicit boundary.

    >>> validate_live_semantic_fields(("entry", 0x1000), tuple)
    """

    if type(value) is not expected_type:
        raise TypeError(
            f"expected {expected_type.__name__}, got {type(value).__name__}",
        )
    _validate_canonical_value(value)
    record_deep_validation()


@dataclass(frozen=True, slots=True)
class CanonicalMaterialization:
    """The canonical representation of one live record, built at a boundary."""

    record: object
    canonical_bytes: bytes


#: Depth of the enclosing ``materialize_for_persistence`` frames.  A
#: ``ContextVar`` rather than a plain global for exactly the reason
#: ``_ACTIVE_SESSION`` is one: the value is per-execution-context, never
#: shared process state.
_MATERIALIZING: ContextVar[int] = ContextVar(
    "d810_authority_materializing", default=0,
)


def materializing() -> bool:
    """Report whether the caller runs inside an explicit materialisation.

    >>> materializing()
    False
    """

    return _MATERIALIZING.get() > 0


def materialize_for_persistence(
    value: object, expected_type: type[object],
) -> CanonicalMaterialization:
    """Build one live record's canonical representation at a named boundary.

    This is the *only* operation that turns a live internal record into its
    persisted form: canonical wire tree, canonical JSON bytes, the strict
    deep validation and the exact decode check, exactly as
    :func:`validate_canonical_roundtrip` has always performed them, so the
    bytes are byte-identical to the ones the same input produced before this
    boundary existed.  It is deliberately not a cached property: crossing the
    boundary is an act the caller performs, not a field a record carries.

    >>> materialize_for_persistence(("entry", 0x1000), tuple).record
    ('entry', 4096)
    """

    token = _MATERIALIZING.set(_MATERIALIZING.get() + 1)
    try:
        encoded = canonical_bytes(value)
        decoded = canonical_decode(encoded)
        if type(decoded) is not expected_type or decoded != value:
            raise ValueError("canonical roundtrip changed the authority value")
    finally:
        _MATERIALIZING.reset(token)
    record_materialization()
    return CanonicalMaterialization(decoded, encoded)


def content_id(schema: str, value: object) -> str:
    if not isinstance(schema, str) or not schema.isascii() or not schema.strip():
        raise ValueError("schema must be non-empty ASCII")
    preimage = _PREFIX + schema.encode("ascii") + b"\0" + canonical_bytes(
        value, _record_lookup=record_content_id_lookup,
    )
    record_content_id_mint()
    return "sha256:" + hashlib.sha256(preimage).hexdigest()


def subject_id(kind: Enum, role: Enum, locator: object) -> str:
    """Compute the subject ID from exactly kind, role, and locator."""

    return content_id(SUBJECT_SCHEMA, (kind, role, locator))


def claim_id(value: object) -> str:
    _ensure_registries()
    if type(value) not in _CLAIM_TYPES:
        raise TypeError("claim_id requires a registered claim record")
    return _record_content_id(CLAIM_SCHEMA, value, "claim_id")


def evidence_id(value: object) -> str:
    _ensure_registries()
    if type(value) not in _EVIDENCE_TYPES:
        raise TypeError("evidence_id requires a registered evidence record")
    return _record_content_id(EVIDENCE_SCHEMA, value, "evidence_id")


def justification_id(value: object) -> str:
    _ensure_registries()
    if type(value) not in _RECORD_TYPES:
        raise TypeError("justification_id requires a registered justification record")
    return _record_content_id(JUSTIFICATION_SCHEMA, value, "justification_id")


def case_id(value: object) -> str:
    _ensure_registries()
    if type(value) not in _RECORD_TYPES:
        raise TypeError("case_id requires a registered safety case record")
    if type(value).__name__ != "SemanticSafetyCase":
        return _record_content_id(CASE_SCHEMA, value, "case_id")
    # A safety case is the transaction's immutable aggregate.  Its children
    # are already sealed by their own content IDs (or inventory/result
    # digests), so re-encoding the complete object graph here is both
    # redundant and quadratic in the common observed-validation path.  Keep
    # the case ID sensitive to every occurrence, but compose it from those
    # sealed child identities.  SemanticSafetyCase.__post_init__ remains the
    # canonical-decode boundary that validates the complete nested content.
    return content_id(CASE_SCHEMA, _semantic_safety_case_projection(value))


def _semantic_safety_case_projection(value: object) -> tuple[tuple[str, object], ...]:
    """Return the compact, complete authority projection of one safety case.

    This helper deliberately has no cache.  The resulting ID is not an
    authority shortcut: every nested record is represented by its own sealed
    content ID/digest, and the model validates its exact parent/child
    relationships before a case is accepted or decoded.
    """

    def occurrence_ids(items: object, attribute: str) -> tuple[object, ...]:
        if type(items) is not tuple:
            return ("invalid-tuple", items)
        return tuple(getattr(item, attribute, item) for item in items)

    compact: dict[str, object] = {}
    for name in _RECORD_FIELDS[type(value)]:
        if name == "case_id":
            continue
        item = getattr(value, name)
        if name == "preparation_receipt":
            compact[name] = getattr(item, "receipt_id", item)
        elif name == "claims":
            compact[name] = occurrence_ids(item, "claim_id")
        elif name == "subjects":
            compact[name] = occurrence_ids(item, "subject_id")
        elif name == "evidence":
            compact[name] = occurrence_ids(item, "evidence_id")
        elif name == "justifications":
            compact[name] = occurrence_ids(item, "justification_id")
        elif name in {"source_inventory", "candidate_inventory"}:
            compact[name] = getattr(item, "inventory_digest", item)
        elif name == "retirement_candidate_catalog":
            compact[name] = None if item is None else getattr(item, "catalog_id", item)
        elif name in {"retirement_phase_result", "corridor_coverage_phase_result"}:
            compact[name] = None if item is None else getattr(item, "result_id", item)
        elif name in {
            "detached_dead_handler_component_source_results",
            "detached_dead_handler_component_phase_results",
            "terminal_cycle_phase_results",
        }:
            compact[name] = occurrence_ids(item, "result_id")
        else:
            # These values have no independently minted content identity.
            # Their field-labelled digest keeps the case sensitive to the
            # complete canonical value without reserializing sibling trees.
            compact[name] = authority_id(("unflatten.case-field.v2", name, item))
    return tuple((name, compact[name]) for name in _RECORD_FIELDS[type(value)] if name != "case_id")


def receipt_id(value: object) -> str:
    _ensure_registries()
    if type(value) not in _RECORD_TYPES:
        raise TypeError("receipt_id requires a registered preparation receipt")
    return _record_content_id(RECEIPT_SCHEMA, value, "receipt_id")


def authority_id(value: object) -> str:
    return content_id(AUTHORITY_SCHEMA, value)


def route_realization_id(value: object) -> str:
    return content_id(ROUTE_REALIZATION_SCHEMA, value)


def cloned_semantic_observation_digest(observation: object) -> str:
    from d810.transforms.unflatten_authority import model as authority_model
    if type(observation) is not authority_model.InventoryInstructionObservation:
        raise TypeError("cloned semantic observation requires exact inventory observation")
    return content_id(
        CLONED_SEMANTIC_OBSERVATION_SCHEMA,
        ("inventory_instruction_observation", observation),
    )


def cloned_semantic_instruction_origin_id(value: object) -> str:
    return content_id(CLONED_SEMANTIC_ORIGIN_SCHEMA, value)


def cloned_semantic_prefix_id(value: object) -> str:
    return content_id(CLONED_SEMANTIC_PREFIX_SCHEMA, value)


def source_route_authority_id(value: object) -> str:
    return content_id(SOURCE_ROUTE_AUTHORITY_SCHEMA, value)


def projected_route_realization_row_id(value: object) -> str:
    return content_id(PROJECTED_ROUTE_ROW_SCHEMA, value)


def projected_route_realization_id(value: object) -> str:
    return content_id(PROJECTED_ROUTE_REALIZATION_SCHEMA, value)


def raw_effect_gate_phase_fact_id(value: object) -> str:
    """Content ID for the serial-free raw effect-gate phase fact."""
    from d810.transforms.unflatten_authority import model
    if type(value) is not model.RawEffectGatePhaseFact:
        raise TypeError("raw effect gate fact ID requires the exact fact type")
    return _record_content_id(RAW_EFFECT_GATE_PHASE_SCHEMA, value, "fact_id")


def effect_site_coordinate_id(value: object) -> str:
    from d810.transforms.unflatten_authority import model
    if type(value) is not model.EffectSiteCoordinate:
        raise TypeError("effect coordinate ID requires the exact coordinate type")
    return content_id(EFFECT_SITE_COORDINATE_SCHEMA, value)


def terminal_site_coordinate_id(value: object) -> str:
    from d810.transforms.unflatten_authority import model
    if type(value) is not model.TerminalSiteCoordinate:
        raise TypeError("terminal coordinate ID requires the exact coordinate type")
    return content_id(TERMINAL_SITE_COORDINATE_SCHEMA, value)


def exact_effect_binding_result_id(value: object) -> str:
    from d810.transforms.unflatten_authority import model
    if type(value) is not model.ExactEffectBindingResult:
        raise TypeError("exact-effect binding ID requires the exact result type")
    return _record_content_id(EXACT_EFFECT_BINDING_SCHEMA, value, "binding_result_id")


def local_alias_binding_result_id(value: object) -> str:
    from d810.transforms.unflatten_authority import model
    if type(value) is not model.LocalAliasScalarizationBindingResult:
        raise TypeError("local-alias binding ID requires the exact result type")
    return _record_content_id(LOCAL_ALIAS_BINDING_SCHEMA, value, "binding_result_id")


def projected_effect_site_result_id(value: object) -> str:
    from d810.transforms.unflatten_authority import model
    if type(value) is not model.ProjectedEffectSiteResult:
        raise TypeError("effect site result ID requires the exact result type")
    return _record_content_id(PROJECTED_EFFECT_SITE_SCHEMA, value, "result_id")


def projected_terminal_site_result_id(value: object) -> str:
    from d810.transforms.unflatten_authority import model
    if type(value) is not model.ProjectedTerminalSiteResult:
        raise TypeError("terminal site result ID requires the exact result type")
    return _record_content_id(PROJECTED_TERMINAL_SITE_SCHEMA, value, "result_id")


def derived_effect_gate_fact_id(raw_effect_gate_fact_id: str, effect_result_ids: tuple[str, ...]) -> str:
    _validate_id(raw_effect_gate_fact_id, "raw_effect_gate_fact_id")
    if type(effect_result_ids) is not tuple or effect_result_ids != tuple(sorted(set(effect_result_ids))):
        raise ValueError("effect_result_ids must be sorted and unique")
    for item in effect_result_ids:
        _validate_id(item, "effect_result_id")
    return content_id(DERIVED_EFFECT_GATE_SCHEMA, (raw_effect_gate_fact_id, effect_result_ids))


def projected_semantic_site_phase_result_id(value: object) -> str:
    from d810.transforms.unflatten_authority import model
    if type(value) is not model.ProjectedSemanticSitePhaseResult:
        raise TypeError("site phase result ID requires the exact result type")
    fields_without_id = tuple(
        (field.name, getattr(value, field.name))
        for field in fields(type(value)) if field.name != "result_id"
    )
    return content_id(PROJECTED_SEMANTIC_SITE_PHASE_SCHEMA, fields_without_id)


def projected_route_site_preservation_id(value: object) -> str:
    from d810.transforms.unflatten_authority import model
    if type(value) is not model.ProjectedRouteSitePreservation:
        raise TypeError("route site preservation ID requires the exact record type")
    fields_without_id = tuple(
        (field.name, getattr(value, field.name))
        for field in fields(type(value)) if field.name != "preservation_id"
    )
    return content_id(PROJECTED_ROUTE_SITE_PRESERVATION_SCHEMA, fields_without_id)


def patch_step_fact_id(value: object) -> str:
    """Content ID for one pre-case patch-step evidence payload."""
    from d810.transforms.unflatten_authority import model
    if type(value) is not model.PatchStepEvidencePayload:
        raise TypeError("patch step fact ID requires PatchStepEvidencePayload")
    return content_id(PATCH_STEP_FACT_SCHEMA, value)


def projected_authority_id(
    *, attempt_id: object,
    proposal_id: str,
    source_authority_id: str,
    plan_id: str,
    claims: tuple[object, ...],
    patch_step_facts: tuple[object, ...],
    source_inventory: object,
    projected_inventory: object,
    raw_effect_gate_fact: object,
    entry_liveness_receipts: tuple[object, ...] = (),
) -> str:
    """Pre-case authority ID over the sealed, scalar input envelope."""
    from d810.transforms.cfg_transaction import (
        LogicalBlockRef, NativeBlockRef, PlanBlockRef, TransactionAttemptId,
    )
    from d810.transforms.unflatten_authority import model
    from d810.transforms.unflatten_authority import bind
    if type(attempt_id) is not TransactionAttemptId:
        raise TypeError("attempt_id must be TransactionAttemptId")
    attempt_id.__post_init__()
    for name, value in (
        ("proposal_id", proposal_id), ("source_authority_id", source_authority_id),
        ("plan_id", plan_id),
    ):
        _validate_id(value, name)
    if (
        type(claims) is not tuple or type(patch_step_facts) is not tuple
        or type(entry_liveness_receipts) is not tuple
    ):
        raise TypeError("claims, patch_step_facts, and receipts must be exact tuples")
    if type(source_inventory) is not model.SemanticGraphInventory or type(projected_inventory) is not model.SemanticGraphInventory:
        raise TypeError("authority inventories must be SemanticGraphInventory")
    model.validate_semantic_graph_inventory(source_inventory)
    model.validate_semantic_graph_inventory(projected_inventory)
    if source_inventory.phase is not model.UnflattenAuthorityPhase.PRODUCER_FORECAST:
        raise ValueError("source inventory must be producer forecast")
    if projected_inventory.phase is not model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT:
        raise ValueError("projected inventory must be projected preflight")
    if attempt_id.plan_id != plan_id:
        raise ValueError("attempt plan does not match authority plan")
    if attempt_id.generation not in (source_inventory.generation, projected_inventory.generation):
        raise ValueError("attempt generation does not match authority inventories")
    if source_inventory.generation != projected_inventory.generation:
        raise ValueError("authority inventories have different generations")
    if attempt_id.generation != source_inventory.generation:
        raise ValueError("attempt generation is not the inventory generation")
    if source_inventory.function_ea != projected_inventory.function_ea:
        raise ValueError("source/projected inventory function lineage mismatch")
    if source_inventory.source_subject_ids != projected_inventory.source_subject_ids:
        raise ValueError("source/projected inventory source subject lineage mismatch")

    claim_types = (
        model.RetiredDispatcherInfrastructureClaim,
        model.DetachedDeadHandlerComponentClaim,
        model.EquivalentSemanticRouteClaim,
        model.ExactInfeasibleEffectClaim,
        model.LocalAliasEffectScalarizationClaim,
        model.TerminalCycleBreakClaim,
    )
    for claim in claims:
        if type(claim) not in claim_types:
            raise TypeError("claims must contain exact closed unflatten claim types")
        claim.__post_init__()
        if claim.source_generation != attempt_id.generation:
            raise ValueError("claim source generation does not match authority generation")
    claim_ids = tuple(claim.claim_id for claim in claims)
    if len(set(claim_ids)) != len(claim_ids) or claim_ids != tuple(sorted(claim_ids)):
        raise ValueError("claims must be sorted by unique claim ID")

    patch_pairs = []
    source_owner_refs = frozenset(
        row.block_ref for row in source_inventory.blocks if row.block_ref is not None
    )
    projected_owner_refs = frozenset(
        row.block_ref for row in projected_inventory.blocks if row.block_ref is not None
    )
    for fact in patch_step_facts:
        if type(fact) is not model.PatchStepEvidencePayload:
            raise TypeError("patch_step_facts must contain exact PatchStepEvidencePayload values")
        fact.__post_init__()
        if fact.plan_id != plan_id:
            raise ValueError("patch step fact belongs to a foreign plan")
        owner_ref = fact.owner_ref
        if type(owner_ref) is LogicalBlockRef:
            if owner_ref.session_id != attempt_id.session_id:
                raise ValueError("logical patch owner session does not match attempt")
            if owner_ref not in source_owner_refs:
                raise ValueError("logical patch owner is absent from source inventory")
        elif type(owner_ref) is NativeBlockRef:
            if owner_ref not in source_owner_refs:
                raise ValueError("native patch owner is absent from source inventory")
        elif type(owner_ref) is PlanBlockRef:
            if owner_ref.plan_id != plan_id:
                raise ValueError("plan patch owner belongs to a foreign plan")
            if owner_ref not in projected_owner_refs:
                raise ValueError("plan patch owner is absent from projected inventory")
        else:
            raise TypeError("patch step owner must be a closed CFG reference")
        patch_pairs.append((patch_step_fact_id(fact), fact))
    input_patch_ids = tuple(pair[0] for pair in patch_pairs)
    patch_pairs = tuple(sorted(patch_pairs, key=lambda pair: pair[0]))
    patch_ids = tuple(pair[0] for pair in patch_pairs)
    if len(set(patch_ids)) != len(patch_ids):
        raise ValueError("patch step fact IDs must be unique")
    if input_patch_ids != patch_ids:
        raise ValueError("patch step fact IDs must be canonical")
    receipt_ids = tuple(receipt.binding_id for receipt in entry_liveness_receipts)
    if any(
        type(receipt) is not model.BoundEntryEndpointLivenessAllowance
        for receipt in entry_liveness_receipts
    ):
        raise TypeError("entry liveness receipts must be exact bound receipts")
    if receipt_ids != tuple(sorted(receipt_ids)) or len(set(receipt_ids)) != len(receipt_ids):
        raise ValueError("entry liveness receipt IDs must be canonical and unique")
    for receipt in entry_liveness_receipts:
        bind.validate_bound_entry_endpoint_liveness_allowance(receipt)

    if type(raw_effect_gate_fact) is not model.RawEffectGatePhaseFact:
        raise TypeError("raw_effect_gate_fact must be RawEffectGatePhaseFact")
    bind.validate_raw_effect_gate_phase_fact(raw_effect_gate_fact)
    if (
        raw_effect_gate_fact.source_inventory_digest != source_inventory.inventory_digest
        or raw_effect_gate_fact.projected_inventory_digest != projected_inventory.inventory_digest
        or raw_effect_gate_fact.source_fingerprint != source_inventory.graph_fingerprint
        or raw_effect_gate_fact.projected_fingerprint != projected_inventory.graph_fingerprint
        or raw_effect_gate_fact.source_generation != source_inventory.generation
        or raw_effect_gate_fact.projected_generation != projected_inventory.generation
    ):
        raise ValueError("raw effect gate fact does not match authority inventories")
    return content_id(PROJECTED_AUTHORITY_SCHEMA, (
        attempt_id, proposal_id, source_authority_id, plan_id,
        claims, patch_pairs,
        (source_inventory.inventory_digest, source_inventory.graph_fingerprint, source_inventory.generation),
        (projected_inventory.inventory_digest, projected_inventory.graph_fingerprint, projected_inventory.generation),
        raw_effect_gate_fact.fact_id,
        receipt_ids,
    ))


def binding_id(value: object) -> str:
    return content_id(BINDING_SCHEMA, value)


def semantic_graph_inventory_digest(*fields: object) -> str:
    """Digest the complete inventory payload, excluding its digest field."""
    # Older call sites construct inventories without observed-only route
    # occurrences.  Canonicalize that absence rather than making every source
    # and projected fixture spell an empty trailing tuple.
    if len(fields) == 13:
        fields = (*fields, (), ())
    elif len(fields) == 14:
        fields = (*fields, ())
    if len(fields) != 15:
        raise TypeError("semantic graph inventory digest requires fifteen fields")
    digest = content_id(SEMANTIC_GRAPH_INVENTORY_SCHEMA, tuple(fields))
    record_inventory_validation()
    return digest


def bound_unflatten_binding_id(prepared: object, patch_binding: object) -> str:
    """Compute the one canonical ID for a prepared live bound plan."""
    return binding_id((
        prepared.authority_id,
        patch_binding.bindings,
        patch_binding.attempt_id,
        patch_binding.maturity.dumps(),
        patch_binding.session_id,
        patch_binding.generation,
        tuple(
            receipt.binding_id
            for receipt in prepared.entry_endpoint_liveness_receipts
        ),
    ))


def _subject_id_from_record(value: object) -> str:
    _ensure_registries()
    if type(value) is not _SUBJECT_TYPE:
        raise TypeError("subject ID requires SemanticSubjectRef")
    return subject_id(value.kind, value.role, value.locator)


def _subject_factory(
    cls: type[object], *, decoded: bool = False, **kwargs: object,
) -> object:
    """Mint one semantic subject, carrying this transaction's reference for it.

    The runtime sidecar is filled in here, from the active canonical
    validation session, and is passed to ``cls(**kwargs)`` as an ordinary
    keyword: the generated ``__init__`` assigns every field -- the sidecar
    included -- *before* it calls ``__post_init__``, so the record is complete
    when it seals.  That ordering is the lifecycle invariant, not a style
    choice: attaching authority to an already-sealed record would be a
    post-seal mutation its own validation could never see.

    Outside a transaction session the reference is ``None``.  That is the
    producer's normal case, not an error -- the emission builds subjects too
    -- and it makes such a subject fail closed at a transaction join instead
    of acquiring an authority no scope ever granted it.

    ``decoded=True`` says the subject is being *reconstructed from a persisted
    payload* rather than constructed live, and it keeps the reference ``None``
    even inside an active session.  The binding design is explicit that
    decoding produces unbound values which require an explicit, named rebind
    before any runtime join: a decoded subject that acquired transaction
    authority merely by being rebuilt while a session happened to be open
    would be exactly the implicit adoption the design forbids, and the
    interning mint would hand it the same reference as a live subject of equal
    content.  ``legacy_codec`` passes it at every site.

    ``subject_id`` is minted exactly as before and stays a non-authoritative
    content fingerprint.
    """

    _ensure_registries()
    if cls is not _SUBJECT_TYPE:
        raise TypeError("subject factory requires SemanticSubjectRef")
    if type(decoded) is not bool:
        raise TypeError("subject factory decode marker must be an exact bool")
    required = {"kind", "role", "block_ref", "anchor_ea", "locator"}
    if set(kwargs) != required:
        raise TypeError("subject factory requires exactly the subject fields")
    minted = subject_id(kwargs["kind"], kwargs["role"], kwargs["locator"])
    kwargs["subject_id"] = minted
    kwargs[RUNTIME_SUBJECT_SIDECAR_FIELD] = (
        None if decoded else transaction_subject_ref(minted)
    )
    return cls(**kwargs)


def _record_content_id(schema: str, value: object, omitted_field: str) -> str:
    if not is_dataclass(value) or isinstance(value, type):
        raise TypeError("content ID factory requires a registered record")
    session = active_canonical_session()
    stamp = None if session is None else _occurrence_guard(session, value)
    if session is not None:
        cached = session.cached_content_id(value, schema, omitted_field, stamp)
        record_content_id_lookup(cached is not None)
        if cached is not None:
            record_content_id_reuse()
            return cached
    _ensure_registries()
    if type(value) not in _RECORD_TYPES:
        raise TypeError(f"unregistered record type: {type(value).__name__}")
    names = _RECORD_FIELDS.get(type(value))
    if names is None:
        raise TypeError(f"unregistered record type: {type(value).__name__}")
    wire = {
        "t": "record",
        "n": type(value).__name__,
        "v": [
                [name, _wire(getattr(value, name, None))]
            for name in names
            if name != omitted_field
        ],
    }
    record_wire_encode()
    record_content_id_mint()
    result = "sha256:" + hashlib.sha256(
        _PREFIX + schema.encode("ascii") + b"\0" + _json_bytes(wire)
    ).hexdigest()
    if session is not None:
        session.store_content_id(value, schema, omitted_field, stamp, result)
    return result


def _claim_factory(
    cls: type[object],
    *args: object,
    runtime_refs: object = None,
    **kwargs: object,
) -> object:
    """Mint one claim, optionally carrying the runtime refs it was built from.

    ``runtime_refs`` is the keyword-only *sidecar channel*: the caller that
    holds the route bundle passes the references its binding already minted,
    so the claim carries a join authority without re-minting, rendering or
    round-tripping anything.  The sidecar is outside ``_RECORD_FIELDS``, so no
    canonical byte and no content ID moves -- ``claim_id`` stays exactly the
    content fingerprint it was.

    The slot is written **before** the ID is minted and before
    ``__post_init__`` runs, because this factory builds with
    ``object.__new__`` and per-field ``object.__setattr__``: a record must be
    complete when it seals, and attaching authority afterwards would be a
    post-seal mutation that the record's own validation could never see.  For
    the same reason a claim type that declares the slot always gets it
    written, ``None`` included -- a generic ``dataclasses.fields`` walker
    reads it by name and an unwritten slot raises.
    """

    _ensure_registries()
    declared = _RECORD_FIELDS.get(cls)
    if declared is None or "claim_id" not in declared:
        raise TypeError("claim factory requires a registered claim record")
    payload_names = tuple(name for name in declared if name != "claim_id")
    carries_sidecar = any(
        field.name == RUNTIME_CLAIM_SIDECAR_FIELD for field in fields(cls)
    )
    if runtime_refs is not None and not carries_sidecar:
        raise TypeError(
            "claim factory sidecar requires a claim record that declares one"
        )
    if args and kwargs:
        raise TypeError("claim factory accepts positional or keyword fields, not both")
    optional_defaults = {
        field.name: field.default
        for field in fields(cls)
        if field.default is not MISSING
    }
    if args:
        required_names = tuple(
            name for name in payload_names if name not in optional_defaults
        )
        if not len(required_names) <= len(args) <= len(payload_names):
            raise TypeError("claim factory received the wrong number of fields")
        kwargs = dict(zip(payload_names, args))
        kwargs.update({
            name: default for name, default in optional_defaults.items()
            if name in payload_names and name not in kwargs
        })
    elif set(kwargs) != set(payload_names):
            missing = set(payload_names) - set(kwargs)
            if missing and missing <= set(optional_defaults):
                kwargs.update({name: optional_defaults[name] for name in missing})
            else:
                raise TypeError("claim factory requires every non-ID field exactly once")
    raw = object.__new__(cls)
    for name in payload_names:
        object.__setattr__(raw, name, kwargs[name])
    if carries_sidecar:
        object.__setattr__(raw, RUNTIME_CLAIM_SIDECAR_FIELD, runtime_refs)
    object.__setattr__(raw, "claim_id", "sha256:" + "0" * 64)
    object.__setattr__(raw, "claim_id", claim_id(raw))
    try:
        cls.__post_init__(raw)
    except (TypeError, ValueError):
        try:
            normalized_id = claim_id(raw)
        except (TypeError, ValueError):
            raise
        if normalized_id == raw.claim_id:
            raise
        kwargs = {name: getattr(raw, name) for name in payload_names}
        kwargs["claim_id"] = normalized_id
        if carries_sidecar:
            kwargs[RUNTIME_CLAIM_SIDECAR_FIELD] = runtime_refs
        return cls(**kwargs)
    return raw


def _evidence_factory(cls: type[object], *args: object, **kwargs: object) -> object:
    _ensure_registries()
    declared = _RECORD_FIELDS.get(cls)
    if declared is None or "evidence_id" not in declared:
        raise TypeError("evidence factory requires a registered evidence record")
    payload_names = tuple(name for name in declared if name != "evidence_id")
    if args and kwargs:
        raise TypeError("evidence factory accepts positional or keyword fields, not both")
    optional_defaults = {
        field.name: field.default
        for field in fields(cls)
        if field.default is not MISSING
    }
    if args:
        required_names = tuple(
            name for name in payload_names if name not in optional_defaults
        )
        if not len(required_names) <= len(args) <= len(payload_names):
            raise TypeError("evidence factory received the wrong number of fields")
        kwargs = dict(zip(payload_names, args))
        kwargs.update({
            name: default for name, default in optional_defaults.items()
            if name in payload_names and name not in kwargs
        })
    elif set(kwargs) != set(payload_names):
        missing = set(payload_names) - set(kwargs)
        if missing and missing <= set(optional_defaults):
            kwargs.update({name: optional_defaults[name] for name in missing})
        else:
            raise TypeError("evidence factory requires every non-ID field exactly once")
    raw = object.__new__(cls)
    for name in payload_names:
        object.__setattr__(raw, name, kwargs[name])
    object.__setattr__(raw, "evidence_id", "sha256:" + "0" * 64)
    object.__setattr__(raw, "evidence_id", evidence_id(raw))
    try:
        cls.__post_init__(raw)
    except (TypeError, ValueError):
        try:
            normalized_id = evidence_id(raw)
        except (TypeError, ValueError):
            raise
        if normalized_id == raw.evidence_id:
            raise
        kwargs = {name: getattr(raw, name) for name in payload_names}
        kwargs["evidence_id"] = normalized_id
        return cls(**kwargs)
    return raw


def _justification_factory(cls: type[object], **kwargs: object) -> object:
    _ensure_registries()
    names = _RECORD_FIELDS.get(cls)
    if cls.__name__ != "AuthorityJustification" or names is None:
        raise TypeError("justification factory requires AuthorityJustification")
    payload = {name: kwargs[name] for name in names if name != "justification_id"}
    if set(kwargs) != set(payload):
        raise TypeError("justification factory accepts only non-ID fields")
    raw = object.__new__(cls)
    for name, value in payload.items():
        object.__setattr__(raw, name, value)
    object.__setattr__(raw, "justification_id", "sha256:" + "0" * 64)
    return cls(justification_id=justification_id(raw), **payload)


def _case_factory(cls: type[object], **kwargs: object) -> object:
    _ensure_registries()
    names = _RECORD_FIELDS.get(cls)
    if cls.__name__ != "SemanticSafetyCase" or names is None:
        raise TypeError("case factory requires SemanticSafetyCase")
    optional_defaults = {
        "detached_dead_handler_component_phase_results": (),
        "terminal_cycle_phase_results": (),
    }
    payload_names = tuple(name for name in names if name != "case_id")
    required_names = set(payload_names) - set(optional_defaults)
    if set(kwargs) - set(payload_names) or required_names - set(kwargs):
        raise TypeError("case factory accepts only non-ID fields")
    payload = {
        name: kwargs.get(name, optional_defaults[name])
        if name in optional_defaults
        else kwargs[name]
        for name in payload_names
    }
    raw = object.__new__(cls)
    for name, value in payload.items():
        object.__setattr__(raw, name, value)
    object.__setattr__(raw, "case_id", "sha256:" + "0" * 64)
    return cls(case_id=case_id(raw), **payload)


def _graph_projection(graph: object, *, blocks: Mapping[int, BlockSnapshot] | None = None) -> object:
    if type(graph) is not FlowGraph:
        raise TypeError("semantic graph requires FlowGraph")
    return portable_graph_projection(graph, blocks=blocks)


def semantic_graph_fingerprint(graph: FlowGraph) -> str:
    return portable_graph_fingerprint(graph)


def semantic_graph_fingerprint_cached(
    graph: FlowGraph, blocks: Mapping[int, BlockSnapshot],
) -> str:
    """Fingerprint one already-materialized graph block snapshot."""
    if type(blocks) is not dict:
        raise TypeError("cached graph blocks must be an exact dict")
    return portable_graph_fingerprint(graph, blocks=blocks)


__all__ = [
    "BlockRecord", "CLAIM_SCHEMA", "DigestFixture", "DIGEST_FIXTURE_SCHEMA",
    "EVIDENCE_SCHEMA", "GraphRecord", "InsnRecord", "MopRecord", "SEMANTIC_GRAPH_SCHEMA",
    "SUBJECT_SCHEMA", "canonical_bytes", "canonical_decode", "validate_canonical_roundtrip",
    "validate_live_semantic_fields", "materialize_for_persistence", "materializing",
    "CanonicalMaterialization", "claim_id", "content_id",
    "evidence_id", "justification_id", "case_id", "authority_id", "binding_id",
    "bound_unflatten_binding_id",
    "semantic_graph_fingerprint", "semantic_graph_fingerprint_cached",
    "semantic_graph_inventory_digest", "subject_id",
    "CLONED_SEMANTIC_OBSERVATION_SCHEMA", "CLONED_SEMANTIC_ORIGIN_SCHEMA",
    "CLONED_SEMANTIC_PREFIX_SCHEMA", "cloned_semantic_observation_digest",
    "cloned_semantic_instruction_origin_id", "cloned_semantic_prefix_id",
]
