"""Compile serial-free Rhad reference operations into portable fragments.

This module is deliberately IDA-free. It validates reference evidence against
an already portable base fragment and emits current ``FragmentPlan`` authority;
live binding and mutation remain backend responsibilities.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import Enum
import hashlib
import json

from d810.core.semantic_route_oracle import (
    ReferenceRouteRewrite,
    RouteOracleRun,
    SemanticTransferKind,
)
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.semantics import PredicateKind, inverted_predicate_kind
from d810.transforms.fragment_plan import (
    FragmentBlockMaterialization,
    FragmentBlockRole,
    FragmentComputedBranchNormalization,
    FragmentConditionalSelectEnvelope,
    FragmentDirectTransferRewrite,
    FragmentEdge,
    FragmentFlagCorridor,
    FragmentOperation,
    FragmentPlan,
    FragmentReferenceRouteAuthority,
    FragmentReferencedImportedConditionalSelectEnvelope,
    FragmentSetccExplicitShiftScaling,
    FragmentSetccIndexExtensionKind,
    FragmentSetccIndexedTableEntry,
    FragmentSetccIndexedTableEvidence,
    FragmentSetccIndexedTableNormalization,
    FragmentSetccScaledLookupScaling,
    FragmentTableByteOrder,
    FragmentTableEntryInterpretation,
    FragmentValueSite,
)


class RhadCompilerRejection(ValueError):
    """Portable reference evidence is incomplete, stale, or unsupported."""


class RhadReferencePhase(str, Enum):
    """Ordered phases used by the pinned Rhad reference implementation."""

    INDIRECT_JUMP_RECONSTRUCTION = "indirect_jump_reconstruction"
    CONSTANT_MATERIALIZATION = "constant_materialization"
    DISPATCHER_ELIMINATION = "dispatcher_elimination"


class RhadOperationCategory(str, Enum):
    """Portable reference-operation categories inventoried for later slices."""

    DIRECT_ROUTE = "direct_route"
    CONDITIONAL_ROUTE = "conditional_route"
    CONSTANT_MATERIALIZATION = "constant_materialization"
    MATERIALIZED_PREDICATE = "materialized_predicate"
    ORDERED_SIDE_EFFECT_CORRIDOR = "ordered_side_effect_corridor"


class RhadOperationVariant(str, Enum):
    """Reference implementation shapes admitted by the portable compiler."""

    CMOV_SELECTED_INDIRECT = "cmov_selected_indirect"
    SIMPLE_INDIRECT_JUMP = "simple_indirect_jump"
    EXISTING_CONDITIONAL_PLUS_INDIRECT = "existing_conditional_plus_indirect"
    SETCC_INDEXED_TABLE = "setcc_indexed_table"


EXPECTED_REFERENCE_PHASE_ORDER = (
    RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    RhadReferencePhase.CONSTANT_MATERIALIZATION,
    RhadReferencePhase.DISPATCHER_ELIMINATION,
)


class RhadReferenceProofArtifactType(str, Enum):
    """Typed immutable proof artifacts admitted by the reference compiler."""

    SETCC_INDEXED_TABLE = "rhad_setcc_indexed_table_proof"


def _identifier(value: str, description: str) -> str:
    normalized = str(value).strip()
    if not normalized:
        raise RhadCompilerRejection(f"{description} must not be empty")
    return normalized


def _native_ea(value: int, description: str) -> int:
    normalized = int(value)
    if not 0 <= normalized < 0xFFFFFFFFFFFFFFFF:
        raise RhadCompilerRejection(f"{description} must be a native EA")
    return normalized


def _ordered_unique_eas(values: tuple[int, ...], description: str) -> tuple[int, ...]:
    normalized = tuple(_native_ea(value, description) for value in values)
    if not normalized or normalized != tuple(sorted(set(normalized))):
        raise RhadCompilerRejection(f"{description} requires ordered unique native EAs")
    return normalized


def _unique_identifiers(
    values: tuple[str, ...],
    description: str,
) -> tuple[str, ...]:
    normalized = tuple(_identifier(value, description) for value in values)
    if not normalized or len(set(normalized)) != len(normalized):
        raise RhadCompilerRejection(f"{description} requires unique identities")
    return normalized


def _require_sha256(value: str, description: str) -> str:
    normalized = str(value).lower()
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise RhadCompilerRejection(f"{description} must be a SHA-256 digest")
    return normalized


def _require_git_commit(value: str, description: str) -> str:
    normalized = str(value).lower()
    if len(normalized) not in {40, 64} or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise RhadCompilerRejection(f"{description} must be a full commit identity")
    return normalized


def _require_mapping_keys(
    value: object,
    expected: frozenset[str],
    description: str,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise RhadCompilerRejection(
            f"{description} requires exact typed fields: {sorted(expected)!r}"
        )
    return value


@dataclass(frozen=True, slots=True)
class RhadSetccIndexedTableProofArtifact:
    """Canonical row-bound table proof required before reference compilation."""

    content_identity: str
    artifact_type: RhadReferenceProofArtifactType
    schema_version: int
    input_sha256: str
    function_ea: int
    reference_commit: str
    operation_id: str
    reference_order: int
    table_evidence: FragmentSetccIndexedTableEvidence

    def __post_init__(self) -> None:
        if self.artifact_type is not RhadReferenceProofArtifactType.SETCC_INDEXED_TABLE:
            raise RhadCompilerRejection(
                "Rhad setcc proof artifact requires its typed artifact kind"
            )
        schema_version = int(self.schema_version)
        if schema_version not in {1, 2}:
            raise RhadCompilerRejection(
                "Rhad setcc proof artifact schema version is unsupported"
            )
        object.__setattr__(self, "schema_version", schema_version)
        object.__setattr__(
            self,
            "input_sha256",
            _require_sha256(self.input_sha256, "Rhad proof input identity"),
        )
        object.__setattr__(
            self,
            "function_ea",
            _native_ea(self.function_ea, "Rhad proof function"),
        )
        object.__setattr__(
            self,
            "reference_commit",
            _require_git_commit(self.reference_commit, "Rhad proof reference commit"),
        )
        object.__setattr__(
            self,
            "operation_id",
            _identifier(self.operation_id, "Rhad proof operation id"),
        )
        reference_order = int(self.reference_order)
        if reference_order < 0:
            raise RhadCompilerRejection(
                "Rhad proof reference order must be non-negative"
            )
        object.__setattr__(self, "reference_order", reference_order)
        if not isinstance(self.table_evidence, FragmentSetccIndexedTableEvidence):
            raise TypeError("Rhad setcc proof artifact requires typed table evidence")
        if schema_version == 1 and not isinstance(
            self.table_evidence.index_scaling,
            FragmentSetccExplicitShiftScaling,
        ):
            raise RhadCompilerRejection(
                "Rhad setcc proof artifact schema 1 requires explicit-shift scaling"
            )
        declared_identity = str(self.content_identity).lower()
        expected_identity = (
            "sha256:"
            + hashlib.sha256(self.canonical_proof_json.encode("utf-8")).hexdigest()
        )
        if declared_identity != expected_identity:
            raise RhadCompilerRejection(
                "Rhad setcc proof artifact content identity is mismatched"
            )
        object.__setattr__(self, "content_identity", expected_identity)

    @property
    def proof_payload(self) -> dict[str, object]:
        evidence = self.table_evidence
        scaling = evidence.index_scaling
        table_payload: dict[str, object] = {
            "additive_key": int(evidence.additive_key),
            "additive_key_producer_ea": int(evidence.additive_key_producer_ea),
            "byte_order": evidence.byte_order.value,
            "decode_ea": int(evidence.decode_ea),
            "entries": [
                {
                    "decoded_target_ea": int(entry.decoded_target_ea),
                    "entry_ea": int(entry.entry_ea),
                    "index": int(entry.index),
                    "raw_value": int(entry.raw_value),
                }
                for entry in evidence.entries
            ],
            "entry_width_bytes": int(evidence.entry_width_bytes),
            "extension_kind": evidence.extension_kind.value,
            "false_index": int(evidence.false_index),
            "index_width_bits": int(evidence.index_width_bits),
            "interpretation": evidence.interpretation.value,
            "lookup_ea": int(evidence.lookup_ea),
            "setcc_destination_width_bits": int(evidence.setcc_destination_width_bits),
            "setcc_ea": int(evidence.setcc_ea),
            "stride_bytes": int(evidence.stride_bytes),
            "table_base_ea": int(evidence.table_base_ea),
            "table_identity": evidence.table_identity,
            "true_index": int(evidence.true_index),
            "zeroed_width_bits": int(evidence.zeroed_width_bits),
            "zeroing_ea": int(evidence.zeroing_ea),
        }
        if int(self.schema_version) == 1:
            if not isinstance(scaling, FragmentSetccExplicitShiftScaling):
                raise RhadCompilerRejection(
                    "Rhad setcc proof artifact schema 1 cannot serialize scaled lookup"
                )
            table_payload.update(
                {
                    "shift_bits": int(scaling.shift_bits),
                    "shift_ea": int(scaling.shift_ea),
                }
            )
        else:
            table_payload["index_scaling"] = (
                {
                    "kind": scaling.kind.value,
                    "shift_bits": int(scaling.shift_bits),
                    "shift_ea": int(scaling.shift_ea),
                }
                if isinstance(scaling, FragmentSetccExplicitShiftScaling)
                else {
                    "kind": scaling.kind.value,
                    "lookup_ea": int(scaling.lookup_ea),
                    "scale_bytes": int(scaling.scale_bytes),
                }
            )
        return {
            "artifact_type": self.artifact_type.value,
            "schema_version": int(self.schema_version),
            "binding": {
                "function_ea": int(self.function_ea),
                "input_sha256": self.input_sha256,
                "operation_id": self.operation_id,
                "reference_commit": self.reference_commit,
                "reference_order": int(self.reference_order),
            },
            "table_evidence": table_payload,
        }

    @property
    def canonical_proof_json(self) -> str:
        return json.dumps(
            self.proof_payload,
            sort_keys=True,
            separators=(",", ":"),
        )

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, object],
    ) -> RhadSetccIndexedTableProofArtifact:
        envelope = _require_mapping_keys(
            value,
            frozenset({"content_identity", "proof"}),
            "Rhad setcc proof artifact envelope",
        )
        proof = _require_mapping_keys(
            envelope["proof"],
            frozenset({"artifact_type", "schema_version", "binding", "table_evidence"}),
            "Rhad setcc proof artifact",
        )
        binding = _require_mapping_keys(
            proof["binding"],
            frozenset(
                {
                    "function_ea",
                    "input_sha256",
                    "operation_id",
                    "reference_commit",
                    "reference_order",
                }
            ),
            "Rhad setcc proof binding",
        )
        try:
            schema_version = int(proof["schema_version"])
        except (TypeError, ValueError) as error:
            raise RhadCompilerRejection(
                "Rhad setcc proof artifact schema version is invalid"
            ) from error
        common_table_fields = {
            "additive_key",
            "additive_key_producer_ea",
            "byte_order",
            "decode_ea",
            "entries",
            "entry_width_bytes",
            "extension_kind",
            "false_index",
            "index_width_bits",
            "interpretation",
            "lookup_ea",
            "setcc_destination_width_bits",
            "setcc_ea",
            "stride_bytes",
            "table_base_ea",
            "table_identity",
            "true_index",
            "zeroed_width_bits",
            "zeroing_ea",
        }
        scaling_fields = (
            {"shift_bits", "shift_ea"} if schema_version == 1 else {"index_scaling"}
        )
        table = _require_mapping_keys(
            proof["table_evidence"],
            frozenset(common_table_fields | scaling_fields),
            "Rhad setcc table evidence",
        )
        raw_entries = table["entries"]
        if not isinstance(raw_entries, list):
            raise RhadCompilerRejection(
                "Rhad setcc table proof entries require an ordered list"
            )
        entries = tuple(
            FragmentSetccIndexedTableEntry(
                **_require_mapping_keys(
                    entry,
                    frozenset({"decoded_target_ea", "entry_ea", "index", "raw_value"}),
                    "Rhad setcc table proof entry",
                )
            )
            for entry in raw_entries
        )
        if schema_version == 1:
            index_scaling = FragmentSetccExplicitShiftScaling(
                shift_ea=int(table["shift_ea"]),
                shift_bits=int(table["shift_bits"]),
            )
        else:
            scaling_payload = _require_mapping_keys(
                table["index_scaling"],
                (
                    frozenset({"kind", "shift_bits", "shift_ea"})
                    if isinstance(table["index_scaling"], Mapping)
                    and table["index_scaling"].get("kind") == "explicit_shift"
                    else frozenset({"kind", "lookup_ea", "scale_bytes"})
                ),
                "Rhad setcc index scaling",
            )
            if scaling_payload["kind"] == "explicit_shift":
                index_scaling = FragmentSetccExplicitShiftScaling(
                    shift_ea=int(scaling_payload["shift_ea"]),
                    shift_bits=int(scaling_payload["shift_bits"]),
                )
            elif scaling_payload["kind"] == "scaled_lookup":
                index_scaling = FragmentSetccScaledLookupScaling(
                    lookup_ea=int(scaling_payload["lookup_ea"]),
                    scale_bytes=int(scaling_payload["scale_bytes"]),
                )
            else:
                raise RhadCompilerRejection(
                    "Rhad setcc proof artifact scaling kind is unsupported"
                )
        try:
            evidence = FragmentSetccIndexedTableEvidence(
                table_identity=str(table["table_identity"]),
                zeroing_ea=int(table["zeroing_ea"]),
                zeroed_width_bits=int(table["zeroed_width_bits"]),
                setcc_ea=int(table["setcc_ea"]),
                setcc_destination_width_bits=int(table["setcc_destination_width_bits"]),
                extension_kind=FragmentSetccIndexExtensionKind(
                    str(table["extension_kind"])
                ),
                index_width_bits=int(table["index_width_bits"]),
                index_scaling=index_scaling,
                lookup_ea=int(table["lookup_ea"]),
                table_base_ea=int(table["table_base_ea"]),
                stride_bytes=int(table["stride_bytes"]),
                entry_width_bytes=int(table["entry_width_bytes"]),
                byte_order=FragmentTableByteOrder(str(table["byte_order"])),
                interpretation=FragmentTableEntryInterpretation(
                    str(table["interpretation"])
                ),
                decode_ea=int(table["decode_ea"]),
                additive_key_producer_ea=int(table["additive_key_producer_ea"]),
                additive_key=int(table["additive_key"]),
                true_index=int(table["true_index"]),
                false_index=int(table["false_index"]),
                entries=entries,
            )
            artifact_type = RhadReferenceProofArtifactType(str(proof["artifact_type"]))
        except (TypeError, ValueError) as error:
            raise RhadCompilerRejection(
                f"Rhad setcc proof artifact is invalid: {error}"
            ) from error
        return cls(
            content_identity=str(envelope["content_identity"]),
            artifact_type=artifact_type,
            schema_version=schema_version,
            input_sha256=str(binding["input_sha256"]),
            function_ea=int(binding["function_ea"]),
            reference_commit=str(binding["reference_commit"]),
            operation_id=str(binding["operation_id"]),
            reference_order=int(binding["reference_order"]),
            table_evidence=evidence,
        )


@dataclass(frozen=True, slots=True)
class RhadConditionalRoute:
    """One reference conditional route with explicit native orientation."""

    operation_id: str
    reference_order: int
    operation_variant: RhadOperationVariant
    reference_symbol: str
    source_block_id: str
    source_native_ea: int
    source_block_anchor_ea: int
    transfer_ea: int
    predicate_anchor_ea: int
    normalization_start_ea: int
    condition_producer_ea: int
    conditional_select_ea: int
    selected_value_block_id: str
    join_block_id: str
    observed_predicate_kind: PredicateKind
    predicate_kind: PredicateKind
    true_target_block_id: str
    false_target_block_id: str
    true_target_ea: int
    false_target_ea: int
    comparison_constant: int
    owned_corridor_instruction_eas: tuple[int, ...]
    imported_closure_block_ids: tuple[str, ...]
    boundary_exit_eas: tuple[int, ...]
    flag_corridor_id: str
    phase: RhadReferencePhase
    depends_on: tuple[str, ...] = ()
    category: RhadOperationCategory = RhadOperationCategory.CONDITIONAL_ROUTE

    def __post_init__(self) -> None:
        for field_name in (
            "operation_id",
            "reference_symbol",
            "source_block_id",
            "selected_value_block_id",
            "join_block_id",
            "true_target_block_id",
            "false_target_block_id",
            "flag_corridor_id",
        ):
            object.__setattr__(
                self,
                field_name,
                _identifier(getattr(self, field_name), field_name.replace("_", " ")),
            )
        reference_order = int(self.reference_order)
        if reference_order < 0:
            raise RhadCompilerRejection(
                "Rhad conditional reference order must be non-negative"
            )
        if self.operation_variant is not RhadOperationVariant.CMOV_SELECTED_INDIRECT:
            raise RhadCompilerRejection(
                "Rhad conditional route requires its typed cmov operation variant"
            )
        for field_name in (
            "source_native_ea",
            "source_block_anchor_ea",
            "transfer_ea",
            "predicate_anchor_ea",
            "normalization_start_ea",
            "condition_producer_ea",
            "conditional_select_ea",
            "true_target_ea",
            "false_target_ea",
        ):
            object.__setattr__(
                self,
                field_name,
                _native_ea(getattr(self, field_name), field_name.replace("_", " ")),
            )
        if not isinstance(
            self.observed_predicate_kind, PredicateKind
        ) or not isinstance(
            self.predicate_kind,
            PredicateKind,
        ):
            raise TypeError("Rhad conditional route requires portable predicates")
        if (
            inverted_predicate_kind(self.observed_predicate_kind)
            is not self.predicate_kind
        ):
            raise RhadCompilerRejection(
                "Rhad conditional selected-value orientation does not invert to "
                "its semantic predicate"
            )
        if not isinstance(self.phase, RhadReferencePhase):
            raise TypeError("Rhad conditional route requires a reference phase")
        if self.category is not RhadOperationCategory.CONDITIONAL_ROUTE:
            raise RhadCompilerRejection(
                "Rhad conditional route requires its conditional category"
            )
        comparison_constant = int(self.comparison_constant)
        if not 0 <= comparison_constant <= 0xFFFFFFFFFFFFFFFF:
            raise RhadCompilerRejection(
                "Rhad conditional comparison constant is out of range"
            )
        corridor = _ordered_unique_eas(
            tuple(self.owned_corridor_instruction_eas),
            "Rhad owned corridor",
        )
        required_corridor_eas = {
            int(self.condition_producer_ea),
            int(self.predicate_anchor_ea),
            int(self.conditional_select_ea),
            int(self.transfer_ea),
        }
        if not required_corridor_eas.issubset(corridor):
            raise RhadCompilerRejection(
                "Rhad owned corridor lost its producer, predicate, select, or transfer"
            )
        if not (
            corridor[-1] == int(self.transfer_ea)
            and self.source_native_ea < self.transfer_ea
            and self.source_block_anchor_ea
            <= self.condition_producer_ea
            < self.predicate_anchor_ea
            <= self.conditional_select_ea
            < self.transfer_ea
            and self.normalization_start_ea == self.predicate_anchor_ea
        ):
            raise RhadCompilerRejection(
                "Rhad conditional normalization anchors are not ordered"
            )
        if self.true_target_block_id == self.false_target_block_id:
            raise RhadCompilerRejection("Rhad conditional route requires two arms")
        if self.selected_value_block_id == self.join_block_id:
            raise RhadCompilerRejection(
                "Rhad conditional select requires distinct selected and join blocks"
            )
        closure = _unique_identifiers(
            tuple(self.imported_closure_block_ids),
            "Rhad imported closure",
        )
        boundaries = _ordered_unique_eas(
            tuple(self.boundary_exit_eas),
            "Rhad boundary exits",
        )
        dependencies = tuple(
            _identifier(value, "Rhad dependency") for value in self.depends_on
        )
        if len(set(dependencies)) != len(dependencies):
            raise RhadCompilerRejection("Rhad operation dependencies must be unique")
        object.__setattr__(self, "comparison_constant", comparison_constant)
        object.__setattr__(self, "reference_order", reference_order)
        object.__setattr__(self, "owned_corridor_instruction_eas", corridor)
        object.__setattr__(self, "imported_closure_block_ids", closure)
        object.__setattr__(self, "boundary_exit_eas", boundaries)
        object.__setattr__(self, "depends_on", dependencies)


@dataclass(frozen=True, slots=True)
class RhadDirectRoute:
    """One reference direct route replacing an imported indirect transfer."""

    operation_id: str
    reference_operation_id: str
    reference_order: int
    operation_variant: RhadOperationVariant
    reference_symbol: str
    source_block_id: str
    source_native_ea: int
    transfer_ea: int
    owner_anchor_ea: int
    direct_target_block_id: str
    owned_corridor_instruction_eas: tuple[int, ...]
    imported_closure_block_ids: tuple[str, ...]
    boundary_exit_eas: tuple[int, ...]
    phase: RhadReferencePhase
    depends_on: tuple[str, ...] = ()
    category: RhadOperationCategory = RhadOperationCategory.DIRECT_ROUTE

    def __post_init__(self) -> None:
        for field_name in (
            "operation_id",
            "reference_operation_id",
            "reference_symbol",
            "source_block_id",
            "direct_target_block_id",
        ):
            object.__setattr__(
                self,
                field_name,
                _identifier(getattr(self, field_name), field_name.replace("_", " ")),
            )
        if not self.operation_id.startswith("route:"):
            raise RhadCompilerRejection(
                "Rhad direct compiled operation id requires route-proof identity"
            )
        if not self.reference_operation_id.startswith("rhad:route@"):
            raise RhadCompilerRejection(
                "Rhad direct reference operation id requires exact ledger identity"
            )
        reference_order = int(self.reference_order)
        if reference_order < 0:
            raise RhadCompilerRejection(
                "Rhad direct reference order must be non-negative"
            )
        if self.operation_variant is not RhadOperationVariant.SIMPLE_INDIRECT_JUMP:
            raise RhadCompilerRejection(
                "Rhad direct route requires its typed operation variant"
            )
        for field_name in ("source_native_ea", "transfer_ea", "owner_anchor_ea"):
            object.__setattr__(
                self,
                field_name,
                _native_ea(getattr(self, field_name), field_name.replace("_", " ")),
            )
        if not isinstance(self.phase, RhadReferencePhase):
            raise TypeError("Rhad direct route requires a reference phase")
        if self.category is not RhadOperationCategory.DIRECT_ROUTE:
            raise RhadCompilerRejection(
                "Rhad direct route requires its direct category"
            )
        corridor = _ordered_unique_eas(
            tuple(self.owned_corridor_instruction_eas),
            "Rhad owned corridor",
        )
        if (
            corridor[0] != int(self.source_native_ea)
            or corridor[-1] != int(self.transfer_ea)
            or int(self.owner_anchor_ea) not in corridor
        ):
            raise RhadCompilerRejection(
                "Rhad direct corridor must run from its native source through "
                "its source-block anchor to its indirect transfer"
            )
        closure = _unique_identifiers(
            tuple(self.imported_closure_block_ids),
            "Rhad imported closure",
        )
        boundaries = _ordered_unique_eas(
            tuple(self.boundary_exit_eas),
            "Rhad boundary exits",
        )
        dependencies = tuple(
            _identifier(value, "Rhad dependency") for value in self.depends_on
        )
        if len(set(dependencies)) != len(dependencies):
            raise RhadCompilerRejection("Rhad operation dependencies must be unique")
        object.__setattr__(self, "owned_corridor_instruction_eas", corridor)
        object.__setattr__(self, "imported_closure_block_ids", closure)
        object.__setattr__(self, "boundary_exit_eas", boundaries)
        object.__setattr__(self, "depends_on", dependencies)
        object.__setattr__(self, "reference_order", reference_order)

    @property
    def reference_identity_payload(self) -> dict[str, object]:
        """Canonical typed identity shared by producer and compiler hashes."""
        return {
            "compiled_operation_id": self.operation_id,
            "operation_variant": self.operation_variant.value,
            "reference_operation_id": self.reference_operation_id,
            "reference_order": int(self.reference_order),
            "reference_symbol": self.reference_symbol,
        }


@dataclass(frozen=True, slots=True)
class RhadExistingConditionalRoute:
    """One imported native conditional-select followed by an indirect jump."""

    operation_id: str
    reference_order: int
    operation_variant: RhadOperationVariant
    reference_symbol: str
    source_block_id: str
    selected_value_block_id: str
    join_block_id: str
    source_native_ea: int
    source_block_anchor_ea: int
    transfer_ea: int
    condition_producer_ea: int
    predicate_anchor_ea: int
    normalization_start_ea: int
    source_branch_ea: int
    selected_value_ea: int
    observed_predicate_kind: PredicateKind
    predicate_kind: PredicateKind
    true_target_block_id: str
    false_target_block_id: str
    true_target_ea: int
    false_target_ea: int
    comparison_constant: int
    owned_corridor_instruction_eas: tuple[int, ...]
    imported_closure_block_ids: tuple[str, ...]
    boundary_exit_eas: tuple[int, ...]
    flag_corridor_id: str
    phase: RhadReferencePhase
    depends_on: tuple[str, ...]
    category: RhadOperationCategory = RhadOperationCategory.CONDITIONAL_ROUTE

    def __post_init__(self) -> None:
        for field_name in (
            "operation_id",
            "reference_symbol",
            "source_block_id",
            "selected_value_block_id",
            "join_block_id",
            "true_target_block_id",
            "false_target_block_id",
            "flag_corridor_id",
        ):
            object.__setattr__(
                self,
                field_name,
                _identifier(getattr(self, field_name), field_name.replace("_", " ")),
            )
        reference_order = int(self.reference_order)
        if reference_order < 0:
            raise RhadCompilerRejection(
                "Rhad existing conditional reference order must be non-negative"
            )
        if (
            self.operation_variant
            is not RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT
        ):
            raise RhadCompilerRejection(
                "Rhad existing conditional route requires its typed operation variant"
            )
        if self.category is not RhadOperationCategory.CONDITIONAL_ROUTE:
            raise RhadCompilerRejection(
                "Rhad existing conditional route requires its conditional category"
            )
        if not isinstance(self.phase, RhadReferencePhase):
            raise TypeError(
                "Rhad existing conditional route requires a reference phase"
            )
        for field_name in (
            "source_native_ea",
            "source_block_anchor_ea",
            "transfer_ea",
            "condition_producer_ea",
            "predicate_anchor_ea",
            "normalization_start_ea",
            "source_branch_ea",
            "selected_value_ea",
            "true_target_ea",
            "false_target_ea",
        ):
            object.__setattr__(
                self,
                field_name,
                _native_ea(getattr(self, field_name), field_name.replace("_", " ")),
            )
        if not isinstance(
            self.observed_predicate_kind,
            PredicateKind,
        ) or not isinstance(self.predicate_kind, PredicateKind):
            raise TypeError(
                "Rhad existing conditional route requires portable predicates"
            )
        if (
            inverted_predicate_kind(self.observed_predicate_kind)
            is not self.predicate_kind
        ):
            raise RhadCompilerRejection(
                "Rhad existing conditional selected-value orientation does not "
                "invert to its semantic predicate"
            )
        comparison_constant = int(self.comparison_constant)
        if not 0 <= comparison_constant <= 0xFFFFFFFFFFFFFFFF:
            raise RhadCompilerRejection(
                "Rhad existing conditional comparison constant is out of range"
            )
        corridor = _ordered_unique_eas(
            tuple(self.owned_corridor_instruction_eas),
            "Rhad existing conditional corridor",
        )
        required_corridor_eas = {
            int(self.source_native_ea),
            int(self.condition_producer_ea),
            int(self.predicate_anchor_ea),
            int(self.source_branch_ea),
            int(self.selected_value_ea),
            int(self.source_block_anchor_ea),
            int(self.transfer_ea),
        }
        if (
            corridor[0] != int(self.source_native_ea)
            or corridor[-1] != int(self.transfer_ea)
            or not required_corridor_eas.issubset(corridor)
            or self.normalization_start_ea != self.predicate_anchor_ea
            or not (
                self.source_native_ea
                < self.condition_producer_ea
                < self.predicate_anchor_ea
                < self.selected_value_ea
                <= self.source_block_anchor_ea
                < self.transfer_ea
            )
        ):
            raise RhadCompilerRejection(
                "Rhad existing conditional native anchors are ambiguous or out of "
                "corridor order"
            )
        if (
            self.source_block_id == self.selected_value_block_id
            or self.source_block_id == self.join_block_id
            or self.selected_value_block_id == self.join_block_id
        ):
            raise RhadCompilerRejection(
                "Rhad existing conditional source, selected value, and join "
                "require distinct identities"
            )
        if self.true_target_block_id == self.false_target_block_id:
            raise RhadCompilerRejection(
                "Rhad existing conditional route requires complete distinct arms"
            )
        closure = _unique_identifiers(
            tuple(self.imported_closure_block_ids),
            "Rhad imported closure",
        )
        boundaries = _ordered_unique_eas(
            tuple(self.boundary_exit_eas),
            "Rhad boundary exits",
        )
        dependencies = tuple(
            _identifier(value, "Rhad dependency") for value in self.depends_on
        )
        if not dependencies or len(set(dependencies)) != len(dependencies):
            raise RhadCompilerRejection(
                "Rhad existing conditional dependencies must be non-empty and unique"
            )
        object.__setattr__(self, "reference_order", reference_order)
        object.__setattr__(self, "comparison_constant", comparison_constant)
        object.__setattr__(self, "owned_corridor_instruction_eas", corridor)
        object.__setattr__(self, "imported_closure_block_ids", closure)
        object.__setattr__(self, "boundary_exit_eas", boundaries)
        object.__setattr__(self, "depends_on", dependencies)


@dataclass(frozen=True, slots=True)
class RhadSetccIndexedTableRoute:
    """One imported setcc-selected table followed by an indirect jump."""

    operation_id: str
    reference_order: int
    operation_variant: RhadOperationVariant
    reference_symbol: str
    source_block_id: str
    source_native_ea: int
    source_block_anchor_ea: int
    transfer_ea: int
    condition_producer_ea: int
    predicate_anchor_ea: int
    predicate_kind: PredicateKind
    true_target_block_id: str
    false_target_block_id: str
    true_target_ea: int
    false_target_ea: int
    table_proof_artifact: RhadSetccIndexedTableProofArtifact
    owned_corridor_instruction_eas: tuple[int, ...]
    imported_closure_block_ids: tuple[str, ...]
    boundary_exit_eas: tuple[int, ...]
    flag_corridor_id: str
    phase: RhadReferencePhase
    depends_on: tuple[str, ...]
    category: RhadOperationCategory = RhadOperationCategory.CONDITIONAL_ROUTE

    def __post_init__(self) -> None:
        for field_name in (
            "operation_id",
            "reference_symbol",
            "source_block_id",
            "true_target_block_id",
            "false_target_block_id",
            "flag_corridor_id",
        ):
            object.__setattr__(
                self,
                field_name,
                _identifier(getattr(self, field_name), field_name.replace("_", " ")),
            )
        reference_order = int(self.reference_order)
        if reference_order < 0:
            raise RhadCompilerRejection(
                "Rhad setcc table reference order must be non-negative"
            )
        if self.operation_variant is not RhadOperationVariant.SETCC_INDEXED_TABLE:
            raise RhadCompilerRejection(
                "Rhad setcc table route requires its typed operation variant"
            )
        if self.category is not RhadOperationCategory.CONDITIONAL_ROUTE:
            raise RhadCompilerRejection(
                "Rhad setcc table route requires its conditional category"
            )
        if not isinstance(self.phase, RhadReferencePhase):
            raise TypeError("Rhad setcc table route requires a reference phase")
        for field_name in (
            "source_native_ea",
            "source_block_anchor_ea",
            "transfer_ea",
            "condition_producer_ea",
            "predicate_anchor_ea",
            "true_target_ea",
            "false_target_ea",
        ):
            object.__setattr__(
                self,
                field_name,
                _native_ea(getattr(self, field_name), field_name.replace("_", " ")),
            )
        if not isinstance(self.predicate_kind, PredicateKind):
            raise TypeError("Rhad setcc table route requires a portable predicate")
        if self.predicate_kind not in {PredicateKind.SLT, PredicateKind.SGE}:
            raise RhadCompilerRejection(
                "Rhad setcc table route requires a supported signed predicate"
            )
        artifact = self.table_proof_artifact
        if not isinstance(artifact, RhadSetccIndexedTableProofArtifact):
            raise TypeError("Rhad setcc table route requires a typed proof artifact")
        if (
            artifact.operation_id != self.operation_id
            or int(artifact.reference_order) != reference_order
        ):
            raise RhadCompilerRejection(
                "Rhad setcc table proof artifact binding differs from its route"
            )
        table_evidence = artifact.table_evidence
        corridor = _ordered_unique_eas(
            tuple(self.owned_corridor_instruction_eas),
            "Rhad setcc table corridor",
        )
        scaling_eas = (
            {int(table_evidence.index_scaling.shift_ea)}
            if isinstance(
                table_evidence.index_scaling,
                FragmentSetccExplicitShiftScaling,
            )
            else {int(table_evidence.index_scaling.lookup_ea)}
        )
        required_corridor_eas = {
            int(self.source_native_ea),
            int(self.source_block_anchor_ea),
            int(self.condition_producer_ea),
            int(self.predicate_anchor_ea),
            int(table_evidence.zeroing_ea),
            int(table_evidence.setcc_ea),
            int(table_evidence.lookup_ea),
            int(table_evidence.decode_ea),
            int(self.transfer_ea),
        } | scaling_eas
        if (
            corridor[0] != int(self.source_native_ea)
            or corridor[-1] != int(self.transfer_ea)
            or not required_corridor_eas.issubset(corridor)
            or int(self.source_native_ea) != int(self.source_block_anchor_ea)
            or int(self.source_native_ea) != int(table_evidence.zeroing_ea)
            or int(self.condition_producer_ea) >= int(self.predicate_anchor_ea)
            or int(self.predicate_anchor_ea) != int(table_evidence.setcc_ea)
        ):
            raise RhadCompilerRejection(
                "Rhad setcc table native anchors are ambiguous or out of corridor order"
            )
        if int(self.true_target_ea) != int(
            table_evidence.true_entry.decoded_target_ea
        ) or int(self.false_target_ea) != int(
            table_evidence.false_entry.decoded_target_ea
        ):
            raise RhadCompilerRejection(
                "Rhad setcc table derived semantic target disagrees with its route"
            )
        if self.true_target_block_id == self.false_target_block_id or int(
            self.true_target_ea
        ) == int(self.false_target_ea):
            raise RhadCompilerRejection(
                "Rhad setcc table route requires complete distinct arms"
            )
        closure = _unique_identifiers(
            tuple(self.imported_closure_block_ids),
            "Rhad imported closure",
        )
        boundaries = _ordered_unique_eas(
            tuple(self.boundary_exit_eas),
            "Rhad boundary exits",
        )
        dependencies = tuple(
            _identifier(value, "Rhad dependency") for value in self.depends_on
        )
        if not dependencies or len(set(dependencies)) != len(dependencies):
            raise RhadCompilerRejection(
                "Rhad setcc table dependencies must be non-empty and unique"
            )
        object.__setattr__(self, "reference_order", reference_order)
        object.__setattr__(self, "owned_corridor_instruction_eas", corridor)
        object.__setattr__(self, "imported_closure_block_ids", closure)
        object.__setattr__(self, "boundary_exit_eas", boundaries)
        object.__setattr__(self, "depends_on", dependencies)

    @property
    def table_evidence(self) -> FragmentSetccIndexedTableEvidence:
        return self.table_proof_artifact.table_evidence


RhadReferenceOperation = (
    RhadConditionalRoute
    | RhadDirectRoute
    | RhadExistingConditionalRoute
    | RhadSetccIndexedTableRoute
)


@dataclass(frozen=True, slots=True)
class RhadReferenceLedger:
    """Immutable compiler input for one reference-ordered fragment batch."""

    ledger_id: str
    function_ea: int
    native_function_ea: int
    evidence_generation: int
    base_plan: FragmentPlan
    reference_oracle_run: RouteOracleRun
    operations: tuple[RhadReferenceOperation, ...]
    required_boundary_exit_eas: tuple[int, ...]
    reference_provenance: Mapping[str, object]
    unsupported_shape_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        ledger_id = _identifier(self.ledger_id, "Rhad ledger id")
        function_ea = _native_ea(self.function_ea, "Rhad function")
        native_function_ea = _native_ea(
            self.native_function_ea,
            "Rhad native function",
        )
        generation = int(self.evidence_generation)
        if generation < 0:
            raise RhadCompilerRejection("Rhad evidence generation must be non-negative")
        if not isinstance(self.base_plan, FragmentPlan):
            raise TypeError("Rhad ledger requires a portable FragmentPlan")
        if not isinstance(self.reference_oracle_run, RouteOracleRun):
            raise TypeError("Rhad ledger requires a reference oracle run")
        operations = tuple(self.operations)
        if not operations or any(
            not isinstance(
                operation,
                (
                    RhadConditionalRoute,
                    RhadDirectRoute,
                    RhadExistingConditionalRoute,
                    RhadSetccIndexedTableRoute,
                ),
            )
            for operation in operations
        ):
            raise RhadCompilerRejection(
                "Rhad ledger requires admitted reference operations"
            )
        operation_ids = tuple(operation.operation_id for operation in operations)
        if len(set(operation_ids)) != len(operation_ids):
            raise RhadCompilerRejection("Rhad ledger operation ids must be unique")
        boundaries = _ordered_unique_eas(
            tuple(self.required_boundary_exit_eas),
            "Rhad required boundary exits",
        )
        provenance = dict(self.reference_provenance)
        if not provenance:
            raise RhadCompilerRejection("Rhad ledger requires reference provenance")
        unsupported = tuple(
            _identifier(value, "Rhad unsupported shape")
            for value in self.unsupported_shape_ids
        )
        object.__setattr__(self, "ledger_id", ledger_id)
        object.__setattr__(self, "function_ea", function_ea)
        object.__setattr__(self, "native_function_ea", native_function_ea)
        object.__setattr__(self, "evidence_generation", generation)
        object.__setattr__(self, "operations", operations)
        object.__setattr__(self, "required_boundary_exit_eas", boundaries)
        object.__setattr__(self, "reference_provenance", provenance)
        object.__setattr__(self, "unsupported_shape_ids", unsupported)

    @property
    def proof_artifact_identities(self) -> tuple[str, ...]:
        return tuple(
            operation.table_proof_artifact.content_identity
            for operation in self.operations
            if isinstance(operation, RhadSetccIndexedTableRoute)
        )

    @property
    def aggregate_program_identity(self) -> str:
        payload = {
            "direct_reference_identities": [
                operation.reference_identity_payload
                for operation in self.operations
                if isinstance(operation, RhadDirectRoute)
            ],
            "function_ea": int(self.native_function_ea),
            "input_sha256": self.reference_oracle_run.candidate_binary_sha256.lower(),
            "operation_ids": [operation.operation_id for operation in self.operations],
            "proof_artifact_identities": list(self.proof_artifact_identities),
            "reference_commit": self.reference_oracle_run.reference_commit.lower(),
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _validate_ledger(
    ledger: RhadReferenceLedger,
    *,
    expected_evidence_generation: int | None,
) -> None:
    if expected_evidence_generation is not None and int(
        expected_evidence_generation
    ) != int(ledger.evidence_generation):
        raise RhadCompilerRejection(
            "Rhad evidence generation differs from current lifecycle generation"
        )
    if ledger.unsupported_shape_ids:
        raise RhadCompilerRejection(
            "Rhad reference shapes are not admitted: "
            + ", ".join(ledger.unsupported_shape_ids)
        )
    plan = ledger.base_plan
    run = ledger.reference_oracle_run
    if (
        int(plan.native_key.function_rva) != int(ledger.function_ea)
        or int(run.function_ea) != int(ledger.function_ea)
        or plan.native_key.input_identity.lower()
        != f"sha256:{run.candidate_binary_sha256.lower()}"
    ):
        raise RhadCompilerRejection(
            "Rhad ledger, native key, and reference run identify different inputs"
        )
    known_operations: set[str] = set()
    last_phase_index = -1
    phase_index = {
        phase: index for index, phase in enumerate(EXPECTED_REFERENCE_PHASE_ORDER)
    }
    for operation in ledger.operations:
        if isinstance(operation, RhadSetccIndexedTableRoute):
            artifact = operation.table_proof_artifact
            if (
                int(artifact.function_ea) != int(ledger.native_function_ea)
                or artifact.input_sha256
                != ledger.reference_oracle_run.candidate_binary_sha256.lower()
                or artifact.reference_commit
                != ledger.reference_oracle_run.reference_commit.lower()
            ):
                raise RhadCompilerRejection(
                    "Rhad setcc table proof artifact binding differs from the ledger"
                )
        missing_dependencies = tuple(
            dependency
            for dependency in operation.depends_on
            if dependency not in known_operations
        )
        if missing_dependencies:
            raise RhadCompilerRejection(
                "Rhad operation dependency is missing or out of order: "
                + ", ".join(missing_dependencies)
            )
        current_phase_index = phase_index[operation.phase]
        if current_phase_index < last_phase_index:
            raise RhadCompilerRejection("Rhad reference phase order regressed")
        known_operations.add(operation.operation_id)
        last_phase_index = current_phase_index

    imported_blocks = tuple(
        block for block in plan.blocks if block.role is FragmentBlockRole.IMPORTED
    )
    imported_ids = {block.block_id for block in imported_blocks}
    block_positions = {block.block_id: index for index, block in enumerate(plan.blocks)}
    for operation in ledger.operations:
        if not isinstance(operation, RhadSetccIndexedTableRoute):
            continue
        source_position = block_positions.get(operation.source_block_id)
        false_position = block_positions.get(operation.false_target_block_id)
        if (
            source_position is None
            or false_position is None
            or false_position != source_position + 1
        ):
            raise RhadCompilerRejection(
                "Rhad setcc false-target physical adjacency is not proven by "
                f"the portable block order: operation={operation.operation_id!r}"
            )
    closure_ids = {
        block_id
        for operation in ledger.operations
        for block_id in operation.imported_closure_block_ids
    }
    if closure_ids != imported_ids:
        missing = tuple(sorted(imported_ids - closure_ids))
        foreign = tuple(sorted(closure_ids - imported_ids))
        raise RhadCompilerRejection(
            "Rhad operation closure union differs from the portable base fragment: "
            f"missing={missing!r} foreign={foreign!r}"
        )
    internalized_exit_eas = {int(block.semantic_anchor_ea) for block in imported_blocks}
    derived_boundary_exit_eas = tuple(
        sorted(
            {
                int(boundary_ea)
                for operation in ledger.operations
                for boundary_ea in operation.boundary_exit_eas
            }
            - internalized_exit_eas
        )
    )
    if derived_boundary_exit_eas != ledger.required_boundary_exit_eas:
        raise RhadCompilerRejection(
            "Rhad boundary exits differ from derived batch authority"
        )


def _reference_payload(
    ledger: RhadReferenceLedger,
    route: RhadReferenceOperation,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "boundary_exit_eas": list(route.boundary_exit_eas),
        "evidence_generation": int(ledger.evidence_generation),
        "function_ea": int(ledger.function_ea),
        "imported_closure_block_ids": list(route.imported_closure_block_ids),
        "operation_category": route.category.value,
        "operation_id": route.operation_id,
        "owned_corridor_instruction_eas": list(route.owned_corridor_instruction_eas),
        "reference_phase": route.phase.value,
        "reference_provenance": dict(ledger.reference_provenance),
        "transfer_ea": int(route.transfer_ea),
    }
    if isinstance(route, RhadConditionalRoute):
        payload.update(
            {
                "comparison_constant": int(route.comparison_constant),
                "condition_producer_ea": int(route.condition_producer_ea),
                "false_target_block_id": route.false_target_block_id,
                "false_target_ea": int(route.false_target_ea),
                "observed_predicate_kind": route.observed_predicate_kind.value,
                "operation_variant": route.operation_variant.value,
                "predicate_anchor_ea": int(route.predicate_anchor_ea),
                "predicate_kind": route.predicate_kind.value,
                "reference_order": int(route.reference_order),
                "reference_symbol": route.reference_symbol,
                "source_block_anchor_ea": int(route.source_block_anchor_ea),
                "source_native_ea": int(route.source_native_ea),
                "true_target_block_id": route.true_target_block_id,
                "true_target_ea": int(route.true_target_ea),
            }
        )
    elif isinstance(route, RhadDirectRoute):
        payload.update(
            {
                "direct_target_block_id": route.direct_target_block_id,
                "operation_variant": route.operation_variant.value,
                "reference_operation_id": route.reference_operation_id,
                "reference_order": int(route.reference_order),
                "reference_symbol": route.reference_symbol,
                "source_block_anchor_ea": int(route.owner_anchor_ea),
                "source_native_ea": int(route.source_native_ea),
            }
        )
    elif isinstance(route, RhadExistingConditionalRoute):
        payload.update(
            {
                "comparison_constant": int(route.comparison_constant),
                "condition_producer_ea": int(route.condition_producer_ea),
                "false_target_block_id": route.false_target_block_id,
                "observed_predicate_kind": route.observed_predicate_kind.value,
                "operation_variant": route.operation_variant.value,
                "predicate_anchor_ea": int(route.predicate_anchor_ea),
                "predicate_kind": route.predicate_kind.value,
                "reference_order": int(route.reference_order),
                "reference_symbol": route.reference_symbol,
                "source_block_anchor_ea": int(route.source_block_anchor_ea),
                "source_native_ea": int(route.source_native_ea),
                "true_target_ea": int(route.true_target_ea),
                "false_target_ea": int(route.false_target_ea),
                "true_target_block_id": route.true_target_block_id,
            }
        )
    elif isinstance(route, RhadSetccIndexedTableRoute):
        evidence = route.table_evidence
        payload.update(
            {
                "aggregate_program_identity": ledger.aggregate_program_identity,
                "condition_producer_ea": int(route.condition_producer_ea),
                "false_target_block_id": route.false_target_block_id,
                "false_target_ea": int(route.false_target_ea),
                "operation_variant": route.operation_variant.value,
                "predicate_anchor_ea": int(route.predicate_anchor_ea),
                "predicate_kind": route.predicate_kind.value,
                "reference_order": int(route.reference_order),
                "reference_symbol": route.reference_symbol,
                "source_block_anchor_ea": int(route.source_block_anchor_ea),
                "source_native_ea": int(route.source_native_ea),
                "true_target_block_id": route.true_target_block_id,
                "true_target_ea": int(route.true_target_ea),
                "proof_artifact": {
                    "content_identity": route.table_proof_artifact.content_identity,
                    "proof": route.table_proof_artifact.proof_payload,
                },
                "setcc_table": {
                    "additive_key": int(evidence.additive_key),
                    "additive_key_producer_ea": int(evidence.additive_key_producer_ea),
                    "byte_order": evidence.byte_order.value,
                    "decode_ea": int(evidence.decode_ea),
                    "entries": [
                        {
                            "decoded_target_ea": int(entry.decoded_target_ea),
                            "entry_ea": int(entry.entry_ea),
                            "index": int(entry.index),
                            "raw_value": int(entry.raw_value),
                        }
                        for entry in evidence.entries
                    ],
                    "entry_width_bytes": int(evidence.entry_width_bytes),
                    "extension_kind": evidence.extension_kind.value,
                    "false_index": int(evidence.false_index),
                    "index_width_bits": int(evidence.index_width_bits),
                    "interpretation": evidence.interpretation.value,
                    "lookup_ea": int(evidence.lookup_ea),
                    "setcc_destination_width_bits": int(
                        evidence.setcc_destination_width_bits
                    ),
                    "setcc_ea": int(evidence.setcc_ea),
                    "index_scaling": (
                        {
                            "kind": evidence.index_scaling.kind.value,
                            "shift_bits": int(evidence.index_scaling.shift_bits),
                            "shift_ea": int(evidence.index_scaling.shift_ea),
                        }
                        if isinstance(
                            evidence.index_scaling,
                            FragmentSetccExplicitShiftScaling,
                        )
                        else {
                            "kind": evidence.index_scaling.kind.value,
                            "lookup_ea": int(evidence.index_scaling.lookup_ea),
                            "scale_bytes": int(evidence.index_scaling.scale_bytes),
                        }
                    ),
                    "stride_bytes": int(evidence.stride_bytes),
                    "table_base_ea": int(evidence.table_base_ea),
                    "table_identity": evidence.table_identity,
                    "true_index": int(evidence.true_index),
                    "zeroed_width_bits": int(evidence.zeroed_width_bits),
                    "zeroing_ea": int(evidence.zeroing_ea),
                },
            }
        )
    else:
        raise RhadCompilerRejection(
            f"Rhad operation type is unsupported: {type(route).__name__}"
        )
    return payload


def _compile_conditional_route(
    ledger: RhadReferenceLedger,
    route: RhadConditionalRoute,
) -> tuple[FragmentOperation, FragmentFlagCorridor]:
    plan = ledger.base_plan
    block_by_id = {block.block_id: block for block in plan.blocks}
    required_block_ids = {
        route.source_block_id,
        route.selected_value_block_id,
        route.join_block_id,
        route.true_target_block_id,
        route.false_target_block_id,
        *route.imported_closure_block_ids,
    }
    missing = tuple(sorted(required_block_ids - set(block_by_id)))
    if missing:
        raise RhadCompilerRejection(
            "Rhad route block binding is incomplete: " + ", ".join(missing)
        )
    source = block_by_id[route.source_block_id]
    selected = block_by_id[route.selected_value_block_id]
    join = block_by_id[route.join_block_id]
    if (
        source.stable_identity is None
        or selected.stable_identity is None
        or join.stable_identity is None
    ):
        raise RhadCompilerRejection(
            "Rhad conditional source and select envelope require stable identities"
        )
    imported_source = (
        source.role is FragmentBlockRole.IMPORTED
        and source.materialization is FragmentBlockMaterialization.IMPORT_NATIVE
        and source.native_body_id is not None
    )
    replacement_source = source.role is FragmentBlockRole.REPLACEMENT
    if not imported_source and not replacement_source:
        raise RhadCompilerRejection(
            "Rhad conditional source requires typed replacement or imported ownership"
        )
    if imported_source:
        native_body = next(
            (
                body
                for body in plan.native_bodies
                if body.body_id == source.native_body_id
            ),
            None,
        )
        if (
            native_body is None
            or route.operation_id not in native_body.proof_ids
            or plan.work_item_scope is None
            or route.operation_id not in plan.work_item_scope.selected_obligation_ids
            or selected.role is not FragmentBlockRole.IMPORTED
            or join.role is not FragmentBlockRole.IMPORTED
            or selected.native_body_id != native_body.body_id
            or join.native_body_id != native_body.body_id
        ):
            raise RhadCompilerRejection(
                "Rhad imported conditional source lacks native-body operation proof"
            )
    corridor_identities = (
        source.stable_identity,
        selected.stable_identity,
        join.stable_identity,
    )
    if any(
        not any(identity.native_ranges.contains(ea) for identity in corridor_identities)
        for ea in route.owned_corridor_instruction_eas
    ):
        raise RhadCompilerRejection(
            "Rhad route corridor lies outside its typed select envelope"
        )
    if (
        not all(
            source.stable_identity.native_ranges.contains(ea)
            for ea in (
                route.source_block_anchor_ea,
                route.condition_producer_ea,
                route.predicate_anchor_ea,
            )
        )
        or (
            imported_source
            and not source.stable_identity.native_ranges.contains(
                route.source_native_ea
            )
        )
        or route.condition_producer_ea
        not in source.stable_identity.exact_instruction_eas
        or route.predicate_anchor_ea not in source.stable_identity.exact_instruction_eas
        or not selected.stable_identity.native_ranges.contains(
            route.conditional_select_ea
        )
        or route.conditional_select_ea
        not in selected.stable_identity.exact_instruction_eas
        or not join.stable_identity.native_ranges.contains(route.transfer_ea)
        or route.transfer_ea not in join.stable_identity.exact_instruction_eas
    ):
        raise RhadCompilerRejection(
            "Rhad conditional native anchors are ambiguous or outside ownership"
        )
    if any(
        target_id not in route.imported_closure_block_ids
        or block_by_id[target_id].role is not FragmentBlockRole.IMPORTED
        for target_id in (route.true_target_block_id, route.false_target_block_id)
    ):
        raise RhadCompilerRejection(
            "Rhad conditional targets must belong to the imported closure"
        )
    true_target_ea = int(route.true_target_ea)
    false_target_ea = int(route.false_target_ea)
    payload = _reference_payload(ledger, route)
    reference_route = ReferenceRouteRewrite(
        route_id=route.operation_id,
        function_ea=int(ledger.function_ea),
        owner_ea=int(route.predicate_anchor_ea),
        rewrite_anchor_ea=int(route.predicate_anchor_ea),
        corridor=tuple(
            (int(interval.start_ea), int(interval.end_ea))
            for identity in corridor_identities
            for interval in identity.native_ranges.intervals
        ),
        reference_phase=route.phase.value,
        original_transfer_kind=SemanticTransferKind.INDIRECT,
        final_transfer_kind=SemanticTransferKind.CONDITIONAL,
        true_target_ea=true_target_ea,
        false_target_ea=false_target_ea,
        predicate_kind=route.predicate_kind.value,
        reference_ledger_identity=ledger.ledger_id,
        reference_ledger_json=json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ),
    )
    normalization = FragmentComputedBranchNormalization(
        predicate_kind=route.predicate_kind,
        normalization_start_ea=int(route.normalization_start_ea),
        condition_producer_ea=int(route.condition_producer_ea),
        unresolved_transfer_ea=int(route.transfer_ea),
        conditional_select_envelope=(
            FragmentReferencedImportedConditionalSelectEnvelope(
                source_branch_ea=int(route.predicate_anchor_ea),
                selected_value_ea=int(route.conditional_select_ea),
                selected_value_identity=selected.stable_identity,
                join_identity=join.stable_identity,
                selected_value_block_id=route.selected_value_block_id,
                join_block_id=route.join_block_id,
                true_target_reference_ea=int(route.true_target_ea),
                false_target_reference_ea=int(route.false_target_ea),
                true_target_delivery_ea=int(
                    block_by_id[route.true_target_block_id].semantic_anchor_ea
                ),
                false_target_delivery_ea=int(
                    block_by_id[route.false_target_block_id].semantic_anchor_ea
                ),
            )
            if imported_source
            else FragmentConditionalSelectEnvelope(
                predicate_ea=int(route.conditional_select_ea),
                observed_predicate_kind=route.observed_predicate_kind,
                selected_value_block_id=route.selected_value_block_id,
                join_block_id=route.join_block_id,
            )
        ),
    )
    operation = FragmentOperation(
        operation_id=route.operation_id,
        source_block_id=route.source_block_id,
        predicate_anchor_ea=int(route.predicate_anchor_ea),
        edges=(
            FragmentEdge(
                role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                target_block_id=route.true_target_block_id,
            ),
            FragmentEdge(
                role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                target_block_id=route.false_target_block_id,
            ),
        ),
        computed_branch_normalization=normalization,
        reference_route_authority=FragmentReferenceRouteAuthority(
            reference_route=reference_route,
            candidate_rewrite_anchor_ea=int(route.predicate_anchor_ea),
            imported_closure_block_ids=route.imported_closure_block_ids,
        ),
    )
    value_id = f"rhad-flags@0x{route.condition_producer_ea:X}"
    flag_corridor = FragmentFlagCorridor(
        corridor_id=route.flag_corridor_id,
        producer=FragmentValueSite(
            site_id=f"producer@0x{route.condition_producer_ea:X}",
            block_id=route.source_block_id,
            value_id=value_id,
            instruction_ea=int(route.condition_producer_ea),
        ),
        consumer=FragmentValueSite(
            site_id=f"consumer@0x{route.predicate_anchor_ea:X}",
            block_id=route.source_block_id,
            value_id=value_id,
            instruction_ea=int(route.predicate_anchor_ea),
        ),
        block_path=(route.source_block_id,),
        permitted_flag_write_eas=frozenset({int(route.condition_producer_ea)}),
    )
    return operation, flag_corridor


def _compile_direct_route(
    ledger: RhadReferenceLedger,
    route: RhadDirectRoute,
) -> FragmentOperation:
    plan = ledger.base_plan
    block_by_id = {block.block_id: block for block in plan.blocks}
    required_block_ids = {
        route.source_block_id,
        route.direct_target_block_id,
        *route.imported_closure_block_ids,
    }
    missing = tuple(sorted(required_block_ids - set(block_by_id)))
    if missing:
        raise RhadCompilerRejection(
            "Rhad direct route block binding is incomplete: " + ", ".join(missing)
        )
    source = block_by_id[route.source_block_id]
    if (
        source.role is not FragmentBlockRole.IMPORTED
        or source.materialization is not FragmentBlockMaterialization.IMPORT_NATIVE
        or source.stable_identity is None
        or source.native_body_id is None
    ):
        raise RhadCompilerRejection(
            "Rhad direct route source must be an imported native-body identity"
        )
    native_body = next(
        (body for body in plan.native_bodies if body.body_id == source.native_body_id),
        None,
    )
    if native_body is None or route.operation_id not in native_body.proof_ids:
        raise RhadCompilerRejection(
            "Rhad direct route source lacks native-body operation proof"
        )
    if any(
        not any(
            int(native_range.start_ea) <= int(corridor_ea) < int(native_range.end_ea)
            for native_range in native_body.native_ranges
        )
        for corridor_ea in route.owned_corridor_instruction_eas
    ):
        raise RhadCompilerRejection(
            "Rhad direct route corridor lies outside its native body"
        )
    if (
        plan.work_item_scope is None
        or route.operation_id not in plan.work_item_scope.selected_obligation_ids
    ):
        raise RhadCompilerRejection(
            "Rhad direct route is absent from frontend work-item authority"
        )
    if not all(
        source.stable_identity.native_ranges.contains(ea)
        for ea in (route.owner_anchor_ea, route.transfer_ea)
    ):
        raise RhadCompilerRejection(
            "Rhad direct source anchor or transfer lies outside its imported "
            "source identity"
        )
    target = block_by_id[route.direct_target_block_id]
    if (
        route.direct_target_block_id not in route.imported_closure_block_ids
        or target.role is not FragmentBlockRole.IMPORTED
        or target.stable_identity is None
    ):
        raise RhadCompilerRejection(
            "Rhad direct target must belong to its imported closure"
        )
    delivery_region = next(
        interval
        for interval in source.stable_identity.native_ranges.intervals
        if int(interval.start_ea) <= int(route.transfer_ea) < int(interval.end_ea)
    )
    target_ea = int(target.semantic_anchor_ea)
    payload = _reference_payload(ledger, route)
    reference_route = ReferenceRouteRewrite(
        route_id=route.operation_id,
        function_ea=int(ledger.function_ea),
        owner_ea=int(route.owner_anchor_ea),
        rewrite_anchor_ea=int(route.transfer_ea),
        corridor=tuple(
            (int(interval.start_ea), int(interval.end_ea))
            for interval in source.stable_identity.native_ranges.intervals
        ),
        reference_phase=route.phase.value,
        original_transfer_kind=SemanticTransferKind.INDIRECT,
        final_transfer_kind=SemanticTransferKind.DIRECT,
        direct_target_ea=target_ea,
        reference_ledger_identity=ledger.ledger_id,
        reference_ledger_json=json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ),
    )
    return FragmentOperation(
        operation_id=route.operation_id,
        source_block_id=route.source_block_id,
        edges=(
            FragmentEdge(
                role=SemanticEdgeRole.DIRECT,
                target_block_id=route.direct_target_block_id,
            ),
        ),
        direct_transfer_rewrite=FragmentDirectTransferRewrite(
            route_proof_id=route.operation_id.removeprefix("route:"),
            owner_identity=source.stable_identity,
            owner_anchor_ea=int(route.owner_anchor_ea),
            rewrite_anchor_ea=int(route.transfer_ea),
            delivery_region=delivery_region,
            proof_corridor_instruction_eas=route.owned_corridor_instruction_eas,
            superseded_instruction_eas=(int(route.transfer_ea),),
            source_transfer_kind=SemanticTransferKind.INDIRECT,
        ),
        reference_route_authority=FragmentReferenceRouteAuthority(
            reference_route=reference_route,
            candidate_rewrite_anchor_ea=int(route.transfer_ea),
            imported_closure_block_ids=route.imported_closure_block_ids,
        ),
    )


def _compile_existing_conditional_route(
    ledger: RhadReferenceLedger,
    route: RhadExistingConditionalRoute,
) -> tuple[FragmentOperation, FragmentFlagCorridor]:
    plan = ledger.base_plan
    block_by_id = {block.block_id: block for block in plan.blocks}
    required_block_ids = {
        route.source_block_id,
        route.selected_value_block_id,
        route.join_block_id,
        route.true_target_block_id,
        route.false_target_block_id,
        *route.imported_closure_block_ids,
    }
    missing = tuple(sorted(required_block_ids - set(block_by_id)))
    if missing:
        raise RhadCompilerRejection(
            "Rhad existing conditional branch arms or envelope are incomplete: "
            + ", ".join(missing)
        )
    source = block_by_id[route.source_block_id]
    selected = block_by_id[route.selected_value_block_id]
    join = block_by_id[route.join_block_id]
    native_body = next(
        (body for body in plan.native_bodies if body.body_id == source.native_body_id),
        None,
    )
    if (
        source.role is not FragmentBlockRole.IMPORTED
        or source.materialization is not FragmentBlockMaterialization.IMPORT_NATIVE
        or source.stable_identity is None
        or source.native_body_id is None
        or native_body is None
        or route.operation_id not in native_body.proof_ids
    ):
        raise RhadCompilerRejection(
            "Rhad existing conditional source lacks imported native-body "
            "operation proof"
        )
    if (
        selected.role is not FragmentBlockRole.IMPORTED
        or join.role is not FragmentBlockRole.IMPORTED
        or selected.native_body_id != native_body.body_id
        or join.native_body_id != native_body.body_id
        or selected.stable_identity is None
        or join.stable_identity is None
    ):
        raise RhadCompilerRejection(
            "Rhad existing conditional envelope lacks imported-body ownership"
        )
    if (
        plan.work_item_scope is None
        or route.operation_id not in plan.work_item_scope.selected_obligation_ids
    ):
        raise RhadCompilerRejection(
            "Rhad existing conditional route is absent from frontend work-item "
            "authority"
        )
    if any(
        not any(
            int(native_range.start_ea) <= int(corridor_ea) < int(native_range.end_ea)
            for native_range in native_body.native_ranges
        )
        for corridor_ea in route.owned_corridor_instruction_eas
    ):
        raise RhadCompilerRejection(
            "Rhad existing conditional corridor lies outside its native body"
        )
    if any(
        not source.stable_identity.native_ranges.contains(ea)
        for ea in (
            route.source_native_ea,
            route.condition_producer_ea,
            route.predicate_anchor_ea,
            route.source_branch_ea,
        )
    ) or not all(
        ea in source.stable_identity.exact_instruction_eas
        for ea in (route.condition_producer_ea, route.predicate_anchor_ea)
    ):
        raise RhadCompilerRejection(
            "Rhad existing conditional source anchors are ambiguous or out of "
            "corridor ownership"
        )
    if (
        not selected.stable_identity.native_ranges.contains(route.selected_value_ea)
        or route.selected_value_ea not in selected.stable_identity.exact_instruction_eas
        or not join.stable_identity.native_ranges.contains(route.source_block_anchor_ea)
        or not join.stable_identity.native_ranges.contains(route.transfer_ea)
        or route.transfer_ea not in join.stable_identity.exact_instruction_eas
    ):
        raise RhadCompilerRejection(
            "Rhad existing conditional selected-value or join anchors are ambiguous"
        )
    targets = (
        (route.true_target_block_id, route.true_target_ea),
        (route.false_target_block_id, route.false_target_ea),
    )

    def _is_owned_branch_arm(target_id: str, target_ea: int) -> bool:
        target = block_by_id[target_id]
        if (
            target_id in route.imported_closure_block_ids
            and target.role is FragmentBlockRole.IMPORTED
        ):
            return True
        return (
            target_id in plan.roots
            and target.role is FragmentBlockRole.REPLACEMENT
            and target.materialization is FragmentBlockMaterialization.CLONE_PUBLISHED
            and target.replaces_block_id in plan.owned_originals
            and target.stable_identity is not None
            and int(target.semantic_anchor_ea) == int(target_ea)
        )

    if any(
        not _is_owned_branch_arm(target_id, target_ea)
        for target_id, target_ea in targets
    ):
        raise RhadCompilerRejection(
            "Rhad existing conditional requires complete owned branch arms"
        )
    true_target_ea = int(route.true_target_ea)
    false_target_ea = int(route.false_target_ea)
    payload = _reference_payload(ledger, route)
    corridor_identities = (
        source.stable_identity,
        selected.stable_identity,
        join.stable_identity,
    )
    reference_route = ReferenceRouteRewrite(
        route_id=route.operation_id,
        function_ea=int(ledger.function_ea),
        owner_ea=int(route.predicate_anchor_ea),
        rewrite_anchor_ea=int(route.predicate_anchor_ea),
        corridor=tuple(
            (int(interval.start_ea), int(interval.end_ea))
            for identity in corridor_identities
            for interval in identity.native_ranges.intervals
        ),
        reference_phase=route.phase.value,
        original_transfer_kind=SemanticTransferKind.INDIRECT,
        final_transfer_kind=SemanticTransferKind.CONDITIONAL,
        true_target_ea=true_target_ea,
        false_target_ea=false_target_ea,
        predicate_kind=route.predicate_kind.value,
        reference_ledger_identity=ledger.ledger_id,
        reference_ledger_json=json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ),
    )
    operation = FragmentOperation(
        operation_id=route.operation_id,
        source_block_id=route.source_block_id,
        predicate_anchor_ea=int(route.predicate_anchor_ea),
        edges=(
            FragmentEdge(
                role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                target_block_id=route.true_target_block_id,
            ),
            FragmentEdge(
                role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                target_block_id=route.false_target_block_id,
            ),
        ),
        computed_branch_normalization=FragmentComputedBranchNormalization(
            predicate_kind=route.predicate_kind,
            normalization_start_ea=int(route.normalization_start_ea),
            condition_producer_ea=int(route.condition_producer_ea),
            unresolved_transfer_ea=int(route.transfer_ea),
            conditional_select_envelope=(
                FragmentReferencedImportedConditionalSelectEnvelope(
                    source_branch_ea=int(route.source_branch_ea),
                    selected_value_ea=int(route.selected_value_ea),
                    selected_value_identity=selected.stable_identity,
                    join_identity=join.stable_identity,
                    selected_value_block_id=route.selected_value_block_id,
                    join_block_id=route.join_block_id,
                    true_target_reference_ea=int(route.true_target_ea),
                    false_target_reference_ea=int(route.false_target_ea),
                    true_target_delivery_ea=int(
                        block_by_id[route.true_target_block_id].semantic_anchor_ea
                    ),
                    false_target_delivery_ea=int(
                        block_by_id[route.false_target_block_id].semantic_anchor_ea
                    ),
                )
            ),
        ),
        reference_route_authority=FragmentReferenceRouteAuthority(
            reference_route=reference_route,
            candidate_rewrite_anchor_ea=int(route.predicate_anchor_ea),
            imported_closure_block_ids=route.imported_closure_block_ids,
        ),
    )
    value_id = f"rhad-flags@0x{route.condition_producer_ea:X}"
    corridor = FragmentFlagCorridor(
        corridor_id=route.flag_corridor_id,
        producer=FragmentValueSite(
            site_id=f"producer@0x{route.condition_producer_ea:X}",
            block_id=route.source_block_id,
            value_id=value_id,
            instruction_ea=int(route.condition_producer_ea),
        ),
        consumer=FragmentValueSite(
            site_id=f"consumer@0x{route.predicate_anchor_ea:X}",
            block_id=route.source_block_id,
            value_id=value_id,
            instruction_ea=int(route.predicate_anchor_ea),
        ),
        block_path=(route.source_block_id,),
        permitted_flag_write_eas=frozenset({int(route.condition_producer_ea)}),
    )
    return operation, corridor


def _compile_setcc_indexed_table_route(
    ledger: RhadReferenceLedger,
    route: RhadSetccIndexedTableRoute,
) -> tuple[FragmentOperation, FragmentFlagCorridor]:
    plan = ledger.base_plan
    block_by_id = {block.block_id: block for block in plan.blocks}
    required_block_ids = {
        route.source_block_id,
        route.true_target_block_id,
        route.false_target_block_id,
        *route.imported_closure_block_ids,
    }
    missing = tuple(sorted(required_block_ids - set(block_by_id)))
    if missing:
        raise RhadCompilerRejection(
            "Rhad setcc table branch arms or closure are incomplete: "
            + ", ".join(missing)
        )
    source = block_by_id[route.source_block_id]
    native_body = next(
        (body for body in plan.native_bodies if body.body_id == source.native_body_id),
        None,
    )
    if (
        source.role is not FragmentBlockRole.IMPORTED
        or source.materialization is not FragmentBlockMaterialization.IMPORT_NATIVE
        or source.stable_identity is None
        or source.native_body_id is None
        or native_body is None
        or route.operation_id not in native_body.proof_ids
    ):
        raise RhadCompilerRejection(
            "Rhad setcc table source lacks imported native-body operation proof"
        )
    if (
        plan.work_item_scope is None
        or route.operation_id not in plan.work_item_scope.selected_obligation_ids
    ):
        raise RhadCompilerRejection(
            "Rhad setcc table route is absent from frontend work-item authority"
        )
    if any(
        not any(
            int(native_range.start_ea) <= int(corridor_ea) < int(native_range.end_ea)
            for native_range in native_body.native_ranges
        )
        for corridor_ea in route.owned_corridor_instruction_eas
    ):
        raise RhadCompilerRejection(
            "Rhad setcc table corridor lies outside its native body"
        )
    if any(
        not source.stable_identity.native_ranges.contains(ea)
        or ea not in source.stable_identity.exact_instruction_eas
        for ea in route.owned_corridor_instruction_eas
    ):
        raise RhadCompilerRejection(
            "Rhad setcc table source anchors are ambiguous or out of corridor ownership"
        )
    targets = (route.true_target_block_id, route.false_target_block_id)
    if any(
        target_id not in route.imported_closure_block_ids
        or block_by_id[target_id].role is not FragmentBlockRole.IMPORTED
        or block_by_id[target_id].stable_identity is None
        for target_id in targets
    ):
        raise RhadCompilerRejection(
            "Rhad setcc table requires complete imported branch arms"
        )
    if int(block_by_id[route.true_target_block_id].semantic_anchor_ea) != int(
        route.true_target_ea
    ) or int(block_by_id[route.false_target_block_id].semantic_anchor_ea) != int(
        route.false_target_ea
    ):
        raise RhadCompilerRejection(
            "Rhad setcc table delivery targets differ from derived reference targets"
        )
    payload = _reference_payload(ledger, route)
    reference_route = ReferenceRouteRewrite(
        route_id=route.operation_id,
        function_ea=int(ledger.function_ea),
        owner_ea=int(route.predicate_anchor_ea),
        rewrite_anchor_ea=int(route.predicate_anchor_ea),
        corridor=tuple(
            (int(interval.start_ea), int(interval.end_ea))
            for interval in source.stable_identity.native_ranges.intervals
        ),
        reference_phase=route.phase.value,
        original_transfer_kind=SemanticTransferKind.INDIRECT,
        final_transfer_kind=SemanticTransferKind.CONDITIONAL,
        true_target_ea=int(route.true_target_ea),
        false_target_ea=int(route.false_target_ea),
        predicate_kind=route.predicate_kind.value,
        reference_ledger_identity=ledger.ledger_id,
        reference_ledger_json=json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ),
    )
    operation = FragmentOperation(
        operation_id=route.operation_id,
        source_block_id=route.source_block_id,
        predicate_anchor_ea=int(route.predicate_anchor_ea),
        edges=(
            FragmentEdge(
                role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                target_block_id=route.true_target_block_id,
            ),
            FragmentEdge(
                role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                target_block_id=route.false_target_block_id,
            ),
        ),
        computed_branch_normalization=FragmentSetccIndexedTableNormalization(
            predicate_kind=route.predicate_kind,
            normalization_start_ea=int(route.predicate_anchor_ea),
            condition_producer_ea=int(route.condition_producer_ea),
            unresolved_transfer_ea=int(route.transfer_ea),
            table_evidence=route.table_evidence,
        ),
        reference_route_authority=FragmentReferenceRouteAuthority(
            reference_route=reference_route,
            candidate_rewrite_anchor_ea=int(route.predicate_anchor_ea),
            imported_closure_block_ids=route.imported_closure_block_ids,
        ),
    )
    value_id = f"rhad-flags@0x{route.condition_producer_ea:X}"
    corridor = FragmentFlagCorridor(
        corridor_id=route.flag_corridor_id,
        producer=FragmentValueSite(
            site_id=f"producer@0x{route.condition_producer_ea:X}",
            block_id=route.source_block_id,
            value_id=value_id,
            instruction_ea=int(route.condition_producer_ea),
        ),
        consumer=FragmentValueSite(
            site_id=f"consumer@0x{route.predicate_anchor_ea:X}",
            block_id=route.source_block_id,
            value_id=value_id,
            instruction_ea=int(route.predicate_anchor_ea),
        ),
        block_path=(route.source_block_id,),
        permitted_flag_write_eas=frozenset({int(route.condition_producer_ea)}),
    )
    return operation, corridor


def compile_rhad_reference_fragment(
    ledger: RhadReferenceLedger,
    *,
    expected_evidence_generation: int | None = None,
) -> FragmentPlan:
    """Compile one admitted reference batch into current fragment authority."""
    if not isinstance(ledger, RhadReferenceLedger):
        raise TypeError("Rhad compiler requires a RhadReferenceLedger")
    _validate_ledger(
        ledger,
        expected_evidence_generation=expected_evidence_generation,
    )
    operations: list[FragmentOperation] = []
    corridors: list[FragmentFlagCorridor] = []
    for operation in ledger.operations:
        if isinstance(operation, RhadConditionalRoute):
            compiled_operation, corridor = _compile_conditional_route(
                ledger,
                operation,
            )
            operations.append(compiled_operation)
            corridors.append(corridor)
        elif isinstance(operation, RhadDirectRoute):
            operations.append(_compile_direct_route(ledger, operation))
        elif isinstance(operation, RhadExistingConditionalRoute):
            compiled_operation, corridor = _compile_existing_conditional_route(
                ledger,
                operation,
            )
            operations.append(compiled_operation)
            corridors.append(corridor)
        elif isinstance(operation, RhadSetccIndexedTableRoute):
            compiled_operation, corridor = _compile_setcc_indexed_table_route(
                ledger,
                operation,
            )
            operations.append(compiled_operation)
            corridors.append(corridor)
        else:
            raise RhadCompilerRejection(
                f"Rhad operation type is unsupported: {type(operation).__name__}"
            )
    operation_topology_ids = {
        block_id
        for operation in operations
        for block_id in (
            operation.source_block_id,
            *(
                (
                    operation.computed_branch_normalization.conditional_select_envelope.selected_value_block_id,
                    operation.computed_branch_normalization.conditional_select_envelope.join_block_id,
                )
                if operation.computed_branch_normalization is not None
                and isinstance(
                    operation.computed_branch_normalization.conditional_select_envelope,
                    FragmentReferencedImportedConditionalSelectEnvelope,
                )
                else ()
            ),
        )
    }
    native_bodies = tuple(
        replace(
            body,
            terminal_block_ids=tuple(
                block_id
                for block_id in body.terminal_block_ids
                if block_id not in operation_topology_ids
            ),
            preserved_native_transfer_block_ids=tuple(
                block_id
                for block_id in body.preserved_native_transfer_block_ids
                if block_id not in operation_topology_ids
            ),
        )
        for body in ledger.base_plan.native_bodies
    )
    return replace(
        ledger.base_plan,
        plan_id=(
            f"rhad-reference-compiler:{ledger.ledger_id}:"
            f"{ledger.aggregate_program_identity}"
            if ledger.proof_artifact_identities
            else f"rhad-reference-compiler:{ledger.ledger_id}"
        ),
        atomic_group_id=ledger.ledger_id,
        operations=tuple(operations),
        flag_corridors=tuple(ledger.base_plan.flag_corridors) + tuple(corridors),
        native_bodies=native_bodies,
        reference_oracle_run=ledger.reference_oracle_run,
    )


__all__ = [
    "EXPECTED_REFERENCE_PHASE_ORDER",
    "RhadCompilerRejection",
    "RhadConditionalRoute",
    "RhadDirectRoute",
    "RhadExistingConditionalRoute",
    "RhadSetccIndexedTableRoute",
    "RhadOperationCategory",
    "RhadOperationVariant",
    "RhadReferenceLedger",
    "RhadReferenceProofArtifactType",
    "RhadReferenceOperation",
    "RhadSetccIndexedTableProofArtifact",
    "RhadReferencePhase",
    "compile_rhad_reference_fragment",
]
